rule VirTool_WinNT_Popureb_A_2147645944_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Popureb.A"
        threat_id = "2147645944"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Popureb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HookAtapiStartIO, NULL == RealDisk" ascii //weight: 1
        $x_2_2 = {81 ba f8 01 00 00 aa 55 00 00 75 0e 8b 45 a0 83 b8 fc 01 00 00 00 75 02}  //weight: 2, accuracy: High
        $x_1_3 = {01 00 00 0f 83 ?? ?? ?? ?? 68 00 02 00 00 04 00 81 7d ?? 90}  //weight: 1, accuracy: Low
        $x_2_4 = {83 fa 2a 75 10 8b 45 ?? c7 40 0c 40 00 00 00 8b 4d ?? c6 01 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Popureb_B_2147650485_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Popureb.B"
        threat_id = "2147650485"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Popureb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 7e 30 2a 75 0b c7 46 0c 40 00 00 00 c6 46 30 28}  //weight: 1, accuracy: High
        $x_1_2 = "HookAtapiStartIO, NULL == RealDisk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

