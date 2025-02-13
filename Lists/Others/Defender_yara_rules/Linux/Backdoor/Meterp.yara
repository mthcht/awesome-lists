rule Backdoor_Linux_Meterp_A_2147766662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Meterp.gen!A!!Meterp.gen!A"
        threat_id = "2147766662"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Meterp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Meterp: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MeterpreterProcess(MeterpreterChannel)" ascii //weight: 1
        $x_1_2 = "super(MeterpreterSocketUDPClient" ascii //weight: 1
        $x_1_3 = "PythonMeterpreter(transport)" ascii //weight: 1
        $x_1_4 = "add_channel(MeterpreterSocketTCPClient" ascii //weight: 1
        $x_1_5 = "xor_bytes(xor_key" ascii //weight: 1
        $x_1_6 = "runcode(compile" ascii //weight: 1
        $x_1_7 = "met.run()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Linux_Meterp_B_2147766663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Meterp.gen!B!!Meterp.gen!B"
        threat_id = "2147766663"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Meterp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Meterp: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/mettle/mettle/src/main.c" ascii //weight: 2
        $x_1_2 = "process_kill_by_pid" ascii //weight: 1
        $x_1_3 = "--persist [none|install|uninstall] manage persistence" ascii //weight: 1
        $x_1_4 = "--background [0|1] start as a background service" ascii //weight: 1
        $x_2_5 = "mettlesploit" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Linux_Meterp_B_2147766663_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Meterp.gen!B!!Meterp.gen!B"
        threat_id = "2147766663"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Meterp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Meterp: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/mettle/mettle/src/mettle.c" ascii //weight: 1
        $x_1_2 = "/mettle/mettle/src/c2_http.c" ascii //weight: 1
        $x_1_3 = "/mettle/mettle/src/bufferev.c" ascii //weight: 1
        $x_1_4 = "/mettle/mettle/src/channel.c" ascii //weight: 1
        $x_1_5 = "/mettle/mettle/src/coreapi.c" ascii //weight: 1
        $x_1_6 = "/mettle/mettle/src/process.c" ascii //weight: 1
        $x_1_7 = "/mettle/mettle/src/service.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

