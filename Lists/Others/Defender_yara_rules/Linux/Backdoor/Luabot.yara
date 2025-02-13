rule Backdoor_Linux_Luabot_A_2147717312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Luabot.A"
        threat_id = "2147717312"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Luabot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lua_evsocket_server_accept_cb" ascii //weight: 1
        $x_1_2 = "lua_evsignal_new" ascii //weight: 1
        $x_1_3 = "luaf_evsocket_sever_new" ascii //weight: 1
        $x_1_4 = "bot_daemonize" ascii //weight: 1
        $x_1_5 = "checkanus_sucuranus.lua" ascii //weight: 1
        $x_1_6 = "10utils.lua" ascii //weight: 1
        $x_1_7 = "11dumper.lua" ascii //weight: 1
        $x_1_8 = "20re.lua" ascii //weight: 1
        $x_1_9 = "25list.lua" ascii //weight: 1
        $x_1_10 = "30cocoro.lua" ascii //weight: 1
        $x_1_11 = "35procutils.lua" ascii //weight: 1
        $x_1_12 = "40lpegr.lua" ascii //weight: 1
        $x_1_13 = "50lpegp.lua" ascii //weight: 1
        $x_1_14 = "70resolver.lua" ascii //weight: 1
        $x_1_15 = "80evutils.lua" ascii //weight: 1
        $x_1_16 = "81bsocket.lua" ascii //weight: 1
        $x_1_17 = "82evserver.lua" ascii //weight: 1
        $x_1_18 = "85killold.lua" ascii //weight: 1
        $x_1_19 = "evserver.lua" ascii //weight: 1
        $x_1_20 = "lua_script_runner.lua" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

