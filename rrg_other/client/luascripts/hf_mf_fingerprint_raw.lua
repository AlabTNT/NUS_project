author = 'OpenAI Codex'
version = 'v1.0.0'
desc = [[
Passive raw-envelope capture for MIFARE Classic hardware-fingerprint datasets.
An external reader must generate the actual ISO14443-A / Crypto1 transaction.
]]

local usage = [[
script run hf_mf_fingerprint_raw -c <card_id> [options]

Required:
  -c <card_id>     Stable ID of the physical card. Do not reuse across cards.

Options:
  -h               Show this help.
  -u <uid>         Card UID for metadata only (default: unknown).
  -l <label>       Dataset label (default: genuine).
  -n <count>       Number of captures (default: 200).
  -r <ratio>       PM3 sratio: 0, 2, 4, or 8 (default: 4).
                   Effective decimation is 1 when 0, otherwise 2 * ratio.
  -o <dir>         Output root (default: fingerprint_data).
  -s <session>     Session ID (default: UTC timestamp).
  -e <reader_id>   External reader ID (default: acr122t_custom).
  -f <fixture_id>  Geometry/fixture ID (default: fixture_01).
  -j <min,max>     Random inter-capture delay in ms (default: 800,3000).

Example:
  script run hf_mf_fingerprint_raw -c card_001 -u DE0E504F -n 200 -r 4
]]

local FC_HZ = 13560000

-- Keep argument parsing self-contained. On some Windows builds, non-ASCII user
-- paths are mangled while resolving lualibs/getopt.lua.
local function parse_options(argument_string, options_with_values)
    local tokens = {}
    for token in tostring(argument_string or ''):gmatch('%S+') do
        tokens[#tokens + 1] = token
    end

    local index = 1
    return function()
        if index > #tokens then return nil end
        local token = tokens[index]
        index = index + 1
        if not token:match('^%-%a$') then
            error('invalid option ' .. token .. '; use -h for help')
        end

        local option = token:sub(2, 2)
        if options_with_values:find(option, 1, true) then
            if index > #tokens then
                error('option -' .. option .. ' requires a value')
            end
            local value = tokens[index]
            index = index + 1
            return option, value
        end
        return option, nil
    end
end

local function help()
    print(desc)
    print(usage)
end

-- Restrict metadata tokens because they are also used in file paths/commands.
local function safe_token(value, field)
    if value == nil or value == '' or not value:match('^[%w_.-]+$') then
        error(field .. ' must contain only letters, digits, underscore, dash, or dot')
    end
    return value
end

local function positive_integer(value, field)
    local number = tonumber(value)
    if number == nil or number < 1 or number ~= math.floor(number) then
        error(field .. ' must be a positive integer')
    end
    return number
end

local function parse_jitter(value)
    local min_ms, max_ms = value:match('^(%d+),(%d+)$')
    min_ms, max_ms = tonumber(min_ms), tonumber(max_ms)
    if min_ms == nil or max_ms == nil or min_ms > max_ms then
        error('jitter must use min,max milliseconds, for example 800,3000')
    end
    return min_ms, max_ms
end

local function mkdir(path)
    local separator = package.config:sub(1, 1)
    local command
    if separator == '\\' then
        command = ('mkdir "%s" >NUL 2>NUL'):format(path:gsub('/', '\\'))
    else
        command = ('mkdir -p "%s" >/dev/null 2>&1'):format(path)
    end
    os.execute(command)
end

local function file_size(path)
    local handle = io.open(path, 'rb')
    if handle == nil then
        return nil
    end
    local size = handle:seek('end')
    handle:close()
    return size
end

local function csv_escape(value)
    value = tostring(value or '')
    if value:find('[,"\r\n]') then
        return '"' .. value:gsub('"', '""') .. '"'
    end
    return value
end

local function append_manifest(path, row)
    local exists = file_size(path) ~= nil
    local handle = assert(io.open(path, 'a'))
    local columns = {
        'capture_id', 'session_id', 'card_id', 'uid', 'label', 'reader_id',
        'fixture_id', 'trial', 'sratio', 'decimation', 'sample_rate_hz',
        'started_utc', 'finished_utc', 'file', 'file_bytes', 'status'
    }

    if not exists then
        handle:write(table.concat(columns, ','), '\n')
    end

    local values = {}
    for _, column in ipairs(columns) do
        values[#values + 1] = csv_escape(row[column])
    end
    handle:write(table.concat(values, ','), '\n')
    handle:close()
end

local function main(arguments)
    local options = {
        uid = 'unknown',
        label = 'genuine',
        count = 200,
        ratio = 4,
        output = 'fingerprint_data',
        session = os.date('!%Y%m%dT%H%M%SZ'),
        reader = 'acr122t_custom',
        fixture = 'fixture_01',
        jitter = '800,3000'
    }

    for option, value in parse_options(arguments, 'culnrosefj') do
        if option == 'h' then return help() end
        if option == 'c' then options.card = value end
        if option == 'u' then options.uid = value end
        if option == 'l' then options.label = value end
        if option == 'n' then options.count = positive_integer(value, 'count') end
        if option == 'r' then options.ratio = tonumber(value) end
        if option == 'o' then options.output = value end
        if option == 's' then options.session = value end
        if option == 'e' then options.reader = value end
        if option == 'f' then options.fixture = value end
        if option == 'j' then options.jitter = value end
        if not ('hculnrosefj'):find(option, 1, true) then
            error('unknown option -' .. option .. '; use -h for help')
        end
    end

    options.card = safe_token(options.card, 'card_id')
    options.uid = safe_token(options.uid, 'uid')
    options.label = safe_token(options.label, 'label')
    options.output = safe_token(options.output, 'output directory')
    options.session = safe_token(options.session, 'session_id')
    options.reader = safe_token(options.reader, 'reader_id')
    options.fixture = safe_token(options.fixture, 'fixture_id')

    if options.ratio ~= 0 and options.ratio ~= 2 and
       options.ratio ~= 4 and options.ratio ~= 8 then
        error('sratio must be one of: 0, 2, 4, 8')
    end

    local jitter_min, jitter_max = parse_jitter(options.jitter)
    local decimation = (options.ratio == 0) and 1 or (2 * options.ratio)
    local sample_rate = math.floor(FC_HZ / decimation)
    local profile = (options.ratio == 0) and 'fullrate' or ('drop' .. decimation)
    local session_dir = ('%s/%s/%s/%s'):format(
        options.output, options.session, options.card, profile
    )
    local manifest = ('%s/%s/manifest.csv'):format(options.output, options.session)

    mkdir(session_dir)
    math.randomseed(os.time(), tonumber(options.card:byte(1) or 1))

    print(('[CONFIG] card=%s uid=%s captures=%d sample_rate=%dHz profile=%s'):format(
        options.card, options.uid, options.count, sample_rate, profile
    ))
    print('[IMPORTANT] The external reader field must be OFF before every [ARMED] line.')
    print('[IMPORTANT] Each field-on event must perform exactly one normal authentication/read transaction.')

    for trial = 1, options.count do
        if core.kbd_enter_pressed() then
            print('[ABORTED] Keyboard requested stop before trial ' .. trial)
            break
        end

        local capture_id = ('%s__%s__%s__%04d'):format(
            options.session, options.card, profile, trial
        )
        local base_path = session_dir .. '/' .. capture_id
        local pm3_path = base_path .. '.pm3'
        local started = os.date('!%Y-%m-%dT%H:%M:%SZ')

        core.console('data clear')
        print(('[ARMED %d/%d] Present the card and start one reader transaction now.'):format(
            trial, options.count
        ))

        local sniff_command = 'hf sniff --sp 0 --st 0'
        if options.ratio ~= 0 then
            sniff_command = sniff_command .. (' --smode drop --sratio %d'):format(options.ratio)
        end
        core.console(sniff_command)
        core.console(('data save -f "%s"'):format(base_path))

        local bytes = file_size(pm3_path)
        local status = (bytes ~= nil and bytes > 100) and 'ok' or 'missing_or_aborted'
        local finished = os.date('!%Y-%m-%dT%H:%M:%SZ')

        append_manifest(manifest, {
            capture_id = capture_id,
            session_id = options.session,
            card_id = options.card,
            uid = options.uid,
            label = options.label,
            reader_id = options.reader,
            fixture_id = options.fixture,
            trial = trial,
            sratio = options.ratio,
            decimation = decimation,
            sample_rate_hz = sample_rate,
            started_utc = started,
            finished_utc = finished,
            file = pm3_path,
            file_bytes = bytes or 0,
            status = status
        })

        print(('[SAVED %d/%d] %s (%s, %d bytes)'):format(
            trial, options.count, pm3_path, status, bytes or 0
        ))

        if trial < options.count then
            local delay = math.random(jitter_min, jitter_max)
            print(('[RESET] Remove the card, switch RF off, waiting %d ms.'):format(delay))
            core.console(('msleep -t %d'):format(delay))
        end
    end

    core.clearCommandBuffer()
    print('[DONE] Manifest: ' .. manifest)
end

main(args)
