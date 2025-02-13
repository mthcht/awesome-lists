rule VirTool_WinNT_Tedroo_A_2147597369_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Tedroo.A"
        threat_id = "2147597369"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Tedroo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Acept task: Defend process %d" ascii //weight: 1
        $x_1_2 = "Acept task: Hide process %d" ascii //weight: 1
        $x_1_3 = "Acept task: Hide file %d" ascii //weight: 1
        $x_10_4 = {fa 0f 20 c0 89 45 ec 25 ff ff fe ff 0f 22 c0 8b 0d ?? ?? ?? ?? 8b 11 a1 ?? ?? ?? ?? c7 04 82 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 11 a1 ?? ?? ?? ?? c7 04 82 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 11 a1 ?? ?? ?? ?? c7 04 82 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 11 a1 ?? ?? ?? ?? c7 04 82 ?? ?? ?? ?? 8b 45 ec 0f 22 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Tedroo_A_2147597370_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Tedroo.gen!A"
        threat_id = "2147597370"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Tedroo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 0c c7 45 f8 02 00 00 c0 e9 d0 00 00 00 8d 45 ec 50 ff 75 08 53 6a 0b ff d6 85 c0 89 45 f8 0f 85 b9 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {80 3e b8 75 07 8b 76 01 89 31 eb 05 b8 02 00 00 c0 83 c2 04 83 3a 00 8b ca 75 e3 5e c2 04 00 55 8b ec 83 ec 14 a1 18 15 01 00 0f b7 00 3d 93 08 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 8b c6 e8 bb fb ff ff 83 c4 04 84 c0 74 19 e8 6f fc ff ff 84 c0 74 05 e8 e6 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_WinNT_Tedroo_B_2147603172_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Tedroo.gen!B"
        threat_id = "2147603172"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Tedroo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 fb 05 0f 85 b6 00 00 00 8b df 33 c0 89 45 fc 85 db 0f 84 a7 00 00 00 c6 45 fb 00 6a 01 8d 43 38 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

