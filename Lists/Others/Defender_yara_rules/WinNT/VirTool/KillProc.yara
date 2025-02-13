rule VirTool_WinNT_KillProc_A_2147638800_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/KillProc.A"
        threat_id = "2147638800"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "KillProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 3f 00 3f 00 5c 00 4b 00 49 00 4c 00 4c 00 50 00 53 00 5f 00 44 00 72 00 76 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 7c 24 24 04 20 22 00 75 83 65 1c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 45 f0 8b 45 fc 8b 4d f0 01 7d ec 01 7d f4 3b 08 72 ?? eb ?? 8b 45 ec 8b 40 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_KillProc_B_2147658301_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/KillProc.B"
        threat_id = "2147658301"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "KillProc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\RESSDTDOS" wide //weight: 1
        $x_1_2 = {62 75 66 3a 20 6b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 64 72 65 73 73 20 69 73 3a 25 78 00}  //weight: 1, accuracy: High
        $x_1_4 = "ZwTerminateProcess" ascii //weight: 1
        $x_1_5 = {8d 45 08 50 ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 7c [0-2] 8d 45 e8 50 ff 75 08 ff 15 [0-26] 6a (00|02)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

