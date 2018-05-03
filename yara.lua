--[[
yara.lua: A Yara output script for Suricata
Written by Elazar Broad

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org>
]]--

function init (args)
    local needs = {}
    needs['type'] = 'file'
    return needs
end

function setup (args)
    --Ensure that the log path has both a leading and trailing slash
    suricata_log_path = fix_path(SCLogPath())

    -- Configure as needed
    suricata_filestore = suricata_log_path .. 'filestore'
    yara_path = '/usr/bin/yara'
    yara_rules_path = '/usr/share/yara-rules/rules.yar'
    yara_log_name = 'yara.json'

    yara_log = assert(io.open(string.format("%s%s", suricata_log_path, yara_log_name), 'a'))
end

function log (args)
    ret, output = run_yara()
    if ret then
        yara_log:write(output, '\n')
        yara_log:flush()
    end
end

function run_yara ()
    state, stored = SCFileState()
    if stored then
        name, size, magic, md5, sha1, sha256 = SCFileInfo()
        SCLogDebug(string.format('state: %s, stored: %s, name: %s, size: %s, magic: %s, md5: %s, sha1: %s, sha256: %s', state, stored, name, size, magic, md5, sha1, sha256))
        if sha256 ~= nil and string.len(sha256) == 64 then
            local file_path = string.format('%s/%s/%s', 
                                       suricata_filestore, 
                                       string.sub(sha256, 0, 2),
                                       sha256)

            local yara_command = string.format('%s -w %s %s',
                yara_path,
                yara_rules_path,
                file_path)

            local has_rule_hit = false
            local ret = {}
            ret['filename'] = name
            ret['size'] = size
            ret['sha256'] = sha256
            ret['rules'] = {}

            local yara_pipe = assert(io.popen(yara_command))
            yara_output = yara_pipe:read('*a')
            yara_pipe:close()
            for line in yara_output:gmatch('[^\r\n]+') do
                rule, file = string.match(line, '^(.+)[%s]+(.+)$')
                SCLogDebug(string.format("rule: %s, file: %s, filepath: %s", rule, file, file_path)) 
                if rule ~= nil and rule ~= '' and file == file_path then
                    table.insert(ret['rules'], rule)
                    has_rule_hit = true
                end
            end
            
            if has_rule_hit then
                return true, table_to_json(ret)
            else
                os.remove(file_path)
            end
        end
    end
    
    return false, nil
end

function table_to_json (t)
    local s = ''
    local open_char, close_char = '{', '}'
    local have_list = false

    for k, v in pairs(t) do
        if type(v) == 'table' then
            v = table_to_json(v)
        end

        qc = '"'
        if have_list or type(k) == 'number' then
             have_list = true
             s = string.format('%s"%s",', s, v)
        else
            if string.find(v, '^[%[%{]') ~= nil or string.find(v, '^%d+$') ~= nil then
                qc = ''
            end
            s = string.format('%s"%s":%s%s%s,', s, k, qc, v, qc)
        end
    end

    if have_list then
        open_char, close_char = '[', ']'
    end

    --Strip trailing comma
    s = s:sub(1, -2)

    return open_char .. s .. close_char
end

function fix_path(s)
    s = s:gsub('^%/?(.+)', '/%1')
    if s:match('%/$') == nil then
        s = string.format('%s/', s)
    end
    return s
end

function deinit (args)
    yara_log:close()
    SCLogInfo('yara.lua deinit')
end
