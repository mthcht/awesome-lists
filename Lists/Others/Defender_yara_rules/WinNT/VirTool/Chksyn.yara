rule VirTool_WinNT_Chksyn_A_2147598768_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Chksyn.A"
        threat_id = "2147598768"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Chksyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 17 04 00 00 c2 2c 00 85 c0 74 04 01 07 eb 0e c7 45 d8 0f 00 00 c0 eb db 8b de 89 5d d0 ff 75 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Chksyn_A_2147598768_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Chksyn.A"
        threat_id = "2147598768"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Chksyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c6 45 f9 50 c6 45 fa 90 c6 45 fb c3 ff 15 ?? ?? 01 00 88 45 f3 fa 0f 20 c0}  //weight: 3, accuracy: Low
        $x_1_2 = {3d 04 c0 22 00 8b 4e 0c c7 46 1c 48 06 00 00 74 0a bf 10 00 00 c0 89 56 1c eb 20}  //weight: 1, accuracy: High
        $x_1_3 = "\\Device\\sys32dev" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Chksyn_B_2147627826_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Chksyn.B"
        threat_id = "2147627826"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Chksyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 45 83 7d 08 05 75 3f 33 ff 85 f6 74 39 03 36 0f b7 46 38 83 f8 04 7c 27 6a 04 68 ?? ?? 01 00 ff 76 3c e8}  //weight: 1, accuracy: Low
        $x_1_2 = {75 c0 eb 10 85 db 74 05 83 23 00 eb 07 c7 45 30 06 00 00 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

