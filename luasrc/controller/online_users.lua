module("luci.controller.online_users", package.seeall)

local fs = require "nixio.fs"
local http = require "luci.http"
local uci = require("luci.model.uci").cursor()

local LAST_SCAN_FILE = "/tmp/online_users_last_scan"
local SCAN_INTERVAL = 30
local PING_CONCURRENCY = 48
local PING_MAX_HOSTS = 2048
local PING_TARGETS_FILE = "/tmp/online_users_ping_targets"
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

local function shell_quote(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function valid_ifname(name)
    return type(name) == "string" and name:match("^[%w%._:%-]+$") ~= nil
end

local function unique_append(list, seen, value)
    if value and value ~= "" and not seen[value] then
        list[#list + 1] = value
        seen[value] = true
    end
end

local function get_lan_devices()
    local devices = {}
    local seen = {}
    local lan_dev = trim(uci:get("network", "lan", "device") or "")
    local lan_ifname = uci:get("network", "lan", "ifname")

    if valid_ifname(lan_dev) then
        unique_append(devices, seen, lan_dev)
    end

    if type(lan_ifname) == "table" then
        for _, ifn in ipairs(lan_ifname) do
            if valid_ifname(ifn) then
                unique_append(devices, seen, ifn)
            end
        end
    elseif type(lan_ifname) == "string" then
        for _, ifn in ipairs(split_words(lan_ifname)) do
            if valid_ifname(ifn) then
                unique_append(devices, seen, ifn)
            end
        end
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

    fs.writefile(PING_TARGETS_FILE, table.concat(hosts, "\n") .. "\n")
    os.execute(
        "xargs -n1 -P" .. PING_CONCURRENCY
        .. " -I{} ping -c1 -W1 {} >/dev/null 2>&1 < " .. shell_quote(PING_TARGETS_FILE)
        .. " >/dev/null 2>&1"
    )
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

local function parse_ip_neigh(allowed_ifaces)
    local result = {}
    local content = cmd_output("ip -4 neigh show 2>/dev/null")

    for line in content:gmatch("[^\r\n]+") do
        local ip, iface, mac = line:match("^(%d+%.%d+%.%d+%.%d+)%s+dev%s+(%S+).-%slladdr%s+([%x:]+)")
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
        if not primary[mac] then
            primary[mac] = item
        end
    end
    return primary
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
    local content = ""
    local now = os.time()
    local lease_files = get_lease_files()

    for _, path in ipairs(lease_files) do
        if fs.access(path) then
            content = fs.readfile(path) or ""
            if #content > 0 then
                break
            end
        end
    end

    for line in content:gmatch("[^\r\n]+") do
        local expires, mac, ip, hostname = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")

        if mac and ip then
            local mac_up = mac:upper()
            local exp_ts = tonumber(expires) or 0
            local remaining = exp_ts - now

            users[mac_up] = {
                mac = mac_up,
                ip = ip,
                hostname = (hostname and hostname ~= "*" and hostname) or "-",
                online = false,
                iface = "-",
                lease_remaining = (remaining > 0) and remaining or 0
            }
        end
    end

    return users
end

local function merge_users(dhcp_map, arp_map)
    local users = {}

    for mac, lease_user in pairs(dhcp_map) do
        local arp = arp_map[mac]
        if arp then
            lease_user.online = true
            lease_user.iface = arp.iface or "-"
            lease_user.ip = arp.ip or lease_user.ip
        end

        users[#users + 1] = lease_user
    end

    for mac, arp in pairs(arp_map) do
        if not dhcp_map[mac] then
            users[#users + 1] = {
                mac = mac,
                ip = arp.ip or "-",
                hostname = "-",
                online = true,
                iface = arp.iface or "-",
                lease_remaining = 0
            }
        end
    end

    table.sort(users, function(a, b)
        if a.online ~= b.online then
            return a.online
        end

        if a.iface ~= b.iface then
            return a.iface < b.iface
        end

        if a.hostname ~= b.hostname then
            return a.hostname < b.hostname
        end

        return a.ip < b.ip
    end)

    return users
end

function index()
    entry({"admin", "status", "online_users"}, template("online_users/index"), _("Online Users"), 95)
    entry({"admin", "status", "online_users", "data"}, call("action_data")).leaf = true
    entry({"admin", "status", "online_users", "vendors"}, call("action_vendors")).leaf = true
end

function action_data()
    local scan = run_light_scan()
    local lan_devices = get_lan_devices()
    local allowed_ifaces = {}
    for _, dev in ipairs(lan_devices) do
        allowed_ifaces[dev] = true
    end

    local arp_map = parse_arp_table(allowed_ifaces)
    arp_map = merge_arp_sources(arp_map, parse_ip_neigh(allowed_ifaces))
    if not next(arp_map) then
        arp_map = parse_arp_table(nil)
        arp_map = merge_arp_sources(arp_map, parse_ip_neigh(nil))
    end

    local dhcp_map = parse_dhcp_leases()
    local users = merge_users(dhcp_map, arp_map)

    http.prepare_content("application/json")
    http.write_json({
        users = users,
        updated_at = os.time(),
        scan = scan
    })
end

function action_vendors()
    local content = fs.readfile("/usr/share/luci-online-users/oui.json")

    http.prepare_content("application/json")
    if content and #content > 0 then
        http.write(content)
    else
        http.write("{}")
    end
end
