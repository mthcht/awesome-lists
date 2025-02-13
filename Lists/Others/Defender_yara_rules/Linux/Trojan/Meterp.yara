rule Trojan_Linux_Meterp_Gen_2147795278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Meterp.Gen"
        threat_id = "2147795278"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Meterp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/mettle/mettle/src/mettle.c" ascii //weight: 1
        $x_1_2 = "/mettle/mettle/src/c2_http.c" ascii //weight: 1
        $x_1_3 = "/mettle/mettle/src/bufferev.c" ascii //weight: 1
        $x_1_4 = "/mettle/mettle/src/channel.c" ascii //weight: 1
        $x_1_5 = "/mettle/mettle/src/coreapi.c" ascii //weight: 1
        $x_1_6 = "/mettle/mettle/src/process.c" ascii //weight: 1
        $x_1_7 = "/mettle/mettle/src/service.c" ascii //weight: 1
        $x_1_8 = "/mettle/mettle/src/main.c" ascii //weight: 1
        $x_1_9 = "process_kill_by_pid" ascii //weight: 1
        $x_1_10 = "--persist [none|install|uninstall] manage persistence" ascii //weight: 1
        $x_1_11 = "--background [0|1] start as a background service" ascii //weight: 1
        $x_1_12 = "mettlesploit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

