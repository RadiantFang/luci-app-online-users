module("luci.controller.online_users", package.seeall)

local nixio = require "nixio"
local fs = require "nixio.fs"
local http = require "luci.http"
local uci = require("luci.model.uci").cursor()

local LAST_SCAN_FILE = "/tmp/online_users_last_scan"
local SCAN_INTERVAL = 30
local PING_CONCURRENCY = 48
local PING_MAX_HOSTS = 2048
local DEFAULT_LEASE_FILES = {
    "/tmp/dhcp.leases",
    "/tmp/hosts/dhcp.leases"
}

local function trim(s)
    local t = (s or ""):gsub("^%s+", "")
    t = t:gsub("%s+$", "")
    return t
end

local function cmd_output(cmd)
    local f = io.popen(cmd)
    if not f then
        return ""
    end

    local out = f:read("*a") or ""
    f:close()
    return trim(out)
end

local function split_words(s)
    local parts = {}
    for part in (s or ""):gmatch("%S+") do
        parts[#parts + 1] = part
    end

    return parts
end

local function split_lines(s)
    local parts = {}
    for line in (s or ""):gmatch("[^\r\n]+") do
        local t = trim(line)
        if t ~= "" then
            parts[#parts + 1] = t
        end
    end

    return parts
end

local function shell_quote(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function valid_ifname(name)
    return type(name) == "string" and name:match("^[%w%._:%-]+$") ~= nil
end

local function valid_netname(name)
    return type(name) == "string" and name:match("^[%w_%-.]+$") ~= nil
end

local function unique_append(list, seen, value)
    if value and value ~= "" and not seen[value] then
        list[#list + 1] = value
        seen[value] = true
    end
end

local function parse_uci_list(value)
    if type(value) == "table" then
        return value
    end

    if type(value) == "string" then
        return split_words(value)
    end

    return {}
end

local function collect_lan_networks()
    local networks = {}
    local seen = {}

    unique_append(networks, seen, "lan")

    uci:foreach("firewall", "zone", function(s)
        if s.name == "lan" then
            for _, net in ipairs(parse_uci_list(s.network)) do
                if valid_netname(net) then
                    unique_append(networks, seen, net)
                end
            end
        end
    end)

    return networks
end

local function append_bridge_members(dev_name, devices, seen)
    uci:foreach("network", "device", function(s)
        if s.name == dev_name and s.type == "bridge" then
            for _, p in ipairs(parse_uci_list(s.ports)) do
                if valid_ifname(p) then
                    unique_append(devices, seen, p)
                end
            end

            for _, ifn in ipairs(parse_uci_list(s.ifname)) do
                if valid_ifname(ifn) then
                    unique_append(devices, seen, ifn)
                end
            end
        end
    end)
end

local function append_network_devices(net, devices, seen)
    if not valid_netname(net) then
        return
    end

    local net_dev = trim(uci:get("network", net, "device") or "")
    local net_ifname = uci:get("network", net, "ifname")

    if valid_ifname(net_dev) then
        unique_append(devices, seen, net_dev)
        append_bridge_members(net_dev, devices, seen)
    end

    for _, ifn in ipairs(parse_uci_list(net_ifname)) do
        if valid_ifname(ifn) then
            unique_append(devices, seen, ifn)
        end
    end

    local ubus_obj = "network.interface." .. net
    local runtime = cmd_output(
        "ubus call " .. shell_quote(ubus_obj) .. " status 2>/dev/null | "
        .. "jsonfilter -e '@.l3_device' -e '@.device'"
    )

    for _, ifn in ipairs(split_lines(runtime)) do
        if valid_ifname(ifn) then
            unique_append(devices, seen, ifn)
        end
    end
end

local function get_lan_devices()
    local devices = {}
    local seen = {}

    for _, net in ipairs(collect_lan_networks()) do
        append_network_devices(net, devices, seen)
    end

    unique_append(devices, seen, "br-lan")
    return devices
end

local function get_lan_cidrs(devices)
    local cidrs = {}
    local seen = {}

    for _, dev in ipairs(devices) do
        if valid_ifname(dev) then
            local cmd = "ip -o -4 addr show dev " .. shell_quote(dev) .. " 2>/dev/null | awk '{print $4}'"
            local out = cmd_output(cmd)
            for cidr in out:gmatch("[^\r\n]+") do
                local c = trim(cidr)
                if c:match("^%d+%.%d+%.%d+%.%d+/%d+$") and not seen[c] then
                    cidrs[#cidrs + 1] = c
                    seen[c] = true
                end
            end
        end
    end

    return cidrs
end

local function should_scan()
    local now = os.time()
    local last = tonumber(trim(fs.readfile(LAST_SCAN_FILE) or "")) or 0
    if (now - last) < SCAN_INTERVAL then
        return false, "throttled"
    end

    fs.writefile(LAST_SCAN_FILE, tostring(now))
    return true
end

local function ip_to_u32(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if not a or not b or not c or not d then
        return nil
    end

    if a > 255 or b > 255 or c > 255 or d > 255 then
        return nil
    end

    return (((a * 256 + b) * 256 + c) * 256 + d)
end

local function u32_to_ip(n)
    local d = n % 256
    n = (n - d) / 256
    local c = n % 256
    n = (n - c) / 256
    local b = n % 256
    local a = (n - b) / 256

    return string.format("%d.%d.%d.%d", a, b, c, d)
end

local function enumerate_cidr_hosts(cidr)
    local ip, prefix = cidr:match("^(%d+%.%d+%.%d+%.%d+)/(%d+)$")
    prefix = tonumber(prefix)
    if not ip or not prefix or prefix < 0 or prefix > 32 then
        return nil, "invalid_cidr"
    end

    local ip_num = ip_to_u32(ip)
    if not ip_num then
        return nil, "invalid_ip"
    end

    local host_size = 2 ^ (32 - prefix)
    if host_size > (PING_MAX_HOSTS + 2) then
        return nil, "too_many_hosts"
    end

    local network = math.floor(ip_num / host_size) * host_size
    local start_ip
    local end_ip

    if prefix <= 30 then
        start_ip = network + 1
        end_ip = network + host_size - 2
    else
        start_ip = network
        end_ip = network + host_size - 1
    end

    if end_ip < start_ip then
        return {}
    end

    local hosts = {}
    for n = start_ip, end_ip do
        hosts[#hosts + 1] = u32_to_ip(n)
    end

    return hosts
end

local function scan_with_ping_fallback(cidr)
    local hosts, err = enumerate_cidr_hosts(cidr)
    if not hosts then
        return false, err
    end

    if #hosts == 0 then
        return false, "no_hosts"
    end

    local targets_file = os.tmpname()
    if not targets_file or targets_file == "" then
        targets_file = string.format("/tmp/online_users_ping_targets_%d_%d", nixio.getpid(), os.time())
    end

    if not fs.writefile(targets_file, table.concat(hosts, "\n") .. "\n") then
        return false, "tmpfile_failed"
    end

    os.execute(
        "xargs -n1 -P" .. PING_CONCURRENCY
        .. " -I{} ping -c1 -W1 {} >/dev/null 2>&1 < " .. shell_quote(targets_file)
        .. " >/dev/null 2>&1"
    )
    fs.remove(targets_file)

    return true, "ping"
end

local function run_light_scan()
    local can_scan, reason = should_scan()
    if not can_scan then
        return {
            executed = false,
            reason = reason
        }
    end

    local devices = get_lan_devices()
    local cidrs = get_lan_cidrs(devices)
    if #cidrs == 0 then
        return {
            executed = false,
            reason = "no_lan_cidr"
        }
    end

    local methods = {}
    local skipped = 0
    local used_fping = fs.access("/usr/bin/fping")

    if fs.access("/usr/bin/fping") then
        for _, cidr in ipairs(cidrs) do
            os.execute("fping -q -a -g " .. shell_quote(cidr) .. " -r 0 -t 120 >/dev/null 2>&1")
        end
        methods[#methods + 1] = "fping"
    else
        for _, cidr in ipairs(cidrs) do
            local ok, m = scan_with_ping_fallback(cidr)
            if ok and m then
                methods[#methods + 1] = m
            else
                skipped = skipped + 1
            end
        end
    end

    return {
        executed = true,
        reason = (#methods > 0) and "ok" or "scan_skipped",
        method = used_fping and "fping" or "ping",
        cidr_count = #cidrs,
        skipped_cidrs = skipped,
        lan_devices = devices
    }
end

local function parse_arp_table(allowed_ifaces)
    local result = {}
    local content = fs.readfile("/proc/net/arp") or ""

    for line in content:gmatch("[^\r\n]+") do
        local ip, _hw, flags, mac, _mask, iface = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
        if ip and mac and iface and mac ~= "00:00:00:00:00:00" and mac ~= "HW" then
            if flags and flags ~= "0x0" and (not allowed_ifaces or allowed_ifaces[iface]) then
                result[mac:upper()] = {
                    ip = ip,
                    iface = iface
                }
            end
        end
    end

    return result
end

local function is_ipv4(ip)
    return type(ip) == "string" and ip:find(".", 1, true) ~= nil
end

local function parse_ip_neigh(family, allowed_ifaces)
    local result = {}
    local content = cmd_output("ip -" .. family .. " neigh show 2>/dev/null")

    for line in content:gmatch("[^\r\n]+") do
        local ip, iface, mac = line:match("^(%S+)%s+dev%s+(%S+).-%slladdr%s+([%x:]+)")
        if ip and iface and mac and mac ~= "00:00:00:00:00:00" then
            if not allowed_ifaces or allowed_ifaces[iface] then
                result[mac:upper()] = {
                    ip = ip,
                    iface = iface
                }
            end
        end
    end

    return result
end

local function merge_arp_sources(primary, secondary)
    for mac, item in pairs(secondary) do
        local cur = primary[mac]
        if not cur then
            primary[mac] = item
        elseif is_ipv4(item.ip) and not is_ipv4(cur.ip) then
            primary[mac] = item
        end
    end

    return primary
end

local function parse_ip_hostname_map()
    local map = {}
    local paths = {
        "/tmp/hosts/odhcpd",
        "/tmp/hosts/dhcp"
    }

    for _, path in ipairs(paths) do
        local content = fs.readfile(path) or ""
        for line in content:gmatch("[^\r\n]+") do
            if line:sub(1, 1) ~= "#" then
                local ip, host = line:match("^(%S+)%s+(%S+)")
                if ip and host and host ~= "" and host ~= "*" then
                    map[ip] = host
                end
            end
        end
    end

    return map
end

local function collect_mac_hostnames(ip_host_map, ...)
    local mac_host = {}
    local sources = {...}

    for _, src in ipairs(sources) do
        for mac, item in pairs(src or {}) do
            local host = ip_host_map[item.ip or ""]
            if host and host ~= "" and host ~= "*" then
                mac_host[mac] = host
            end
        end
    end

    return mac_host
end

local function get_lease_files()
    local files = {}
    local seen = {}

    local function add(path)
        local p = trim(path)
        if p ~= "" and not seen[p] then
            files[#files + 1] = p
            seen[p] = true
        end
    end

    uci:foreach("dhcp", "dnsmasq", function(s)
        add(s.leasefile)
    end)

    for _, p in ipairs(DEFAULT_LEASE_FILES) do
        add(p)
    end

    return files
end

local function parse_dhcp_leases()
    local users = {}
    local lease_files = get_lease_files()
    for _, path in ipairs(lease_files) do
        if fs.access(path) then
            local content = fs.readfile(path) or ""
            for line in content:gmatch("[^\r\n]+") do
                local _expires, mac, ip, hostname = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
                if mac and ip then
                    local mac_up = mac:upper()
                    local host = (hostname and hostname ~= "*" and hostname) or "-"
                    local cur = users[mac_up]

                    if not cur then
                        users[mac_up] = {
                            mac = mac_up,
                            ip = ip,
                            hostname = host,
                            online = false,
                            iface = "-"
                        }
                    else
                        if cur.hostname == "-" and host ~= "-" then
                            cur.hostname = host
                        end
                        if not is_ipv4(cur.ip) and is_ipv4(ip) then
                            cur.ip = ip
                        end
                    end
                end
            end
        end
    end

    return users
end

local function merge_users(dhcp_map, arp_map, mac_host_map)
    local users = {}

    for mac, lease_user in pairs(dhcp_map) do
        local arp = arp_map[mac]
        if arp then
            lease_user.online = true
            lease_user.iface = arp.iface or "-"
            if not lease_user.ip or lease_user.ip == "-" or (not is_ipv4(lease_user.ip) and is_ipv4(arp.ip)) then
                lease_user.ip = arp.ip or lease_user.ip
            end
        end
        if lease_user.hostname == "-" and mac_host_map[mac] then
            lease_user.hostname = mac_host_map[mac]
        end

        users[#users + 1] = lease_user
    end

    for mac, arp in pairs(arp_map) do
        if not dhcp_map[mac] then
            users[#users + 1] = {
                mac = mac,
                ip = arp.ip or "-",
                hostname = mac_host_map[mac] or "-",
                online = true,
                iface = arp.iface or "-"
            }
        end
    end

    local grouped = {}
    local grouped_list = {}

    for _, user in ipairs(users) do
        local host = trim(user.hostname or "-")
        local key

        if host ~= "-" and host ~= "" then
            key = "host:" .. host:lower()
        else
            key = "mac:" .. (user.mac or "-")
        end

        local g = grouped[key]
        if not g then
            g = {
                hostname = (host ~= "" and host) or "-",
                online = false,
                ip = {},
                mac = {},
                iface = {},
                _seen_ip = {},
                _seen_mac = {},
                _seen_iface = {}
            }
            grouped[key] = g
            grouped_list[#grouped_list + 1] = g
        end

        g.online = g.online or (user.online == true)
        unique_append(g.ip, g._seen_ip, user.ip or "-")
        unique_append(g.mac, g._seen_mac, user.mac or "-")
        unique_append(g.iface, g._seen_iface, user.iface or "-")
    end

    local merged_users = {}
    for _, g in ipairs(grouped_list) do
        local ipv4_list = {}
        local ipv6_list = {}
        for _, ip in ipairs(g.ip) do
            if is_ipv4(ip) then
                ipv4_list[#ipv4_list + 1] = ip
            else
                ipv6_list[#ipv6_list + 1] = ip
            end
        end

        merged_users[#merged_users + 1] = {
            hostname = g.hostname,
            online = g.online,
            ip = (#ipv4_list > 0) and table.concat(ipv4_list, ", ") or table.concat(ipv6_list, ", "),
            mac = table.concat(g.mac, ", "),
            iface = table.concat(g.iface, ", ")
        }
    end

    table.sort(merged_users, function(a, b)
        if a.online ~= b.online then
            return a.online
        end

        if a.hostname ~= b.hostname then
            return a.hostname < b.hostname
        end

        return a.ip < b.ip
    end)

    return merged_users
end

function index()
    entry({"admin", "status", "online_users"}, template("online_users/index"), _("Online Users"), 95)
    entry({"admin", "status", "online_users", "data"}, call("action_data")).leaf = true
end

function action_data()
    local scan = run_light_scan()
    local lan_devices = get_lan_devices()
    local allowed_ifaces = {}
    for _, dev in ipairs(lan_devices) do
        allowed_ifaces[dev] = true
    end

    local arp_map = parse_arp_table(allowed_ifaces)
    local neigh4 = parse_ip_neigh("4", allowed_ifaces)
    local neigh6 = parse_ip_neigh("6", allowed_ifaces)
    arp_map = merge_arp_sources(arp_map, neigh4)
    arp_map = merge_arp_sources(arp_map, neigh6)

    if not next(arp_map) then
        arp_map = parse_arp_table(nil)
        neigh4 = parse_ip_neigh("4", nil)
        neigh6 = parse_ip_neigh("6", nil)
        arp_map = merge_arp_sources(arp_map, neigh4)
        arp_map = merge_arp_sources(arp_map, neigh6)
    end

    local dhcp_map = parse_dhcp_leases()
    local ip_host_map = parse_ip_hostname_map()
    local mac_host_map = collect_mac_hostnames(ip_host_map, neigh6, neigh4, arp_map)
    local users = merge_users(dhcp_map, arp_map, mac_host_map)

    http.prepare_content("application/json")
    http.write_json({
        users = users,
        updated_at = os.time(),
        scan = scan
    })
end
