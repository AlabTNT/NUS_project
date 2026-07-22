author = 'OpenAI Codex'
version = 'v1.0.0'
desc = [[
Capture an ISO14443-A protocol trace from an external reader and MIFARE card.
This is a separate acquisition from raw-envelope capture because one PM3 cannot
run both FPGA modes at the same time.
]]

local usage = [[
script run hf_mf_fingerprint_trace -c <card_id> [options]

Required:
  -c <card_id>     Stable ID of the physical card.

Options:
  -h               Show this help.
  -u <uid>         Card UID for metadata only (default: unknown).
  -l <label>       Dataset label (default: genuine).
  -o <dir>         Output root (default: fingerprint_data).
  -s <session>     Session ID (default: UTC timestamp).
  -e <reader_id>   External reader ID (default: acr122t_custom).
  -t <count>       Intended transactions in this trace (default: 20).

Operation:
  Start the script, run the requested transactions with the external reader,
  then press the Proxmark3 button to stop and save the .trace file.
]]

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

local function json_escape(value)
    return tostring(value):gsub('\\', '\\\\'):gsub('"', '\\"')
end

local function main(arguments)
    local options = {
        uid = 'unknown',
        label = 'genuine',
        output = 'fingerprint_data',
        session = os.date('!%Y%m%dT%H%M%SZ'),
        reader = 'acr122t_custom',
        count = 20
    }

    for option, value in parse_options(arguments, 'culoset') do
        if option == 'h' then return help() end
        if option == 'c' then options.card = value end
        if option == 'u' then options.uid = value end
        if option == 'l' then options.label = value end
        if option == 'o' then options.output = value end
        if option == 's' then options.session = value end
        if option == 'e' then options.reader = value end
        if option == 't' then options.count = positive_integer(value, 'transaction count') end
        if not ('hculoset'):find(option, 1, true) then
            error('unknown option -' .. option .. '; use -h for help')
        end
    end

    options.card = safe_token(options.card, 'card_id')
    options.uid = safe_token(options.uid, 'uid')
    options.label = safe_token(options.label, 'label')
    options.output = safe_token(options.output, 'output directory')
    options.session = safe_token(options.session, 'session_id')
    options.reader = safe_token(options.reader, 'reader_id')

    local trace_dir = ('%s/%s/%s/protocol'):format(
        options.output, options.session, options.card
    )
    mkdir(trace_dir)

    local capture_id = ('%s__%s__protocol'):format(options.session, options.card)
    local base_path = trace_dir .. '/' .. capture_id
    local started = os.date('!%Y-%m-%dT%H:%M:%SZ')

    print(('[ARMED] Capture %d normal transactions for card %s.'):format(
        options.count, options.card
    ))
    print('[STOP] Press the physical Proxmark3 button after the final transaction.')
    core.console('hf 14a sniff -r')
    core.console(('trace save -f "%s"'):format(base_path))

    local metadata_path = base_path .. '.json'
    local handle = assert(io.open(metadata_path, 'w'))
    handle:write(('{\n' ..
        '  "capture_id": "%s",\n' ..
        '  "session_id": "%s",\n' ..
        '  "card_id": "%s",\n' ..
        '  "uid": "%s",\n' ..
        '  "label": "%s",\n' ..
        '  "reader_id": "%s",\n' ..
        '  "intended_transactions": %d,\n' ..
        '  "started_utc": "%s",\n' ..
        '  "finished_utc": "%s",\n' ..
        '  "trace_file": "%s.trace"\n' ..
        '}\n'):format(
            json_escape(capture_id), json_escape(options.session),
            json_escape(options.card), json_escape(options.uid),
            json_escape(options.label), json_escape(options.reader),
            options.count, started, os.date('!%Y-%m-%dT%H:%M:%SZ'),
            json_escape(base_path)
        ))
    handle:close()

    core.clearCommandBuffer()
    print('[DONE] Trace: ' .. base_path .. '.trace')
    print('[DONE] Metadata: ' .. metadata_path)
end

main(args)
