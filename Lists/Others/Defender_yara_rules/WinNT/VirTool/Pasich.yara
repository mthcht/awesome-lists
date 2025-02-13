rule VirTool_WinNT_Pasich_A_2147607326_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Pasich.A"
        threat_id = "2147607326"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Pasich"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 31 30 44 54 6a 30 6a 00 8b f8 ff 15 ?? ?? 40 00 8b f0 85 f6 74 ?? a1 ?? ?? 40 00 6a 01 6a 01 50 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 04 68 00 10 00 00 8d 4c 24 08 51 6a 00 8d 54 24 18 52 6a ff c7 44 24 20 00 00 00 00 c7 44 24 18 18 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_2_3 = {83 65 fc 00 83 65 e4 00 6a 25 e8 ?? ?? 00 00 8b f0 89 75 dc 85 f6 74 ?? c6 45 d4 e9 33 c0 8d 7d d5 ab 8b 45 08 89 45 e0 ff 75 e0}  //weight: 2, accuracy: Low
        $x_2_4 = {83 eb 05 89 5d d5 0f 20 c0 8b c8 81 e1 ff ff fe ff 0f 22 c1 8d 75 d4 a5 a4 0f 22 c0 83 4d fc ff}  //weight: 2, accuracy: High
        $x_2_5 = {8d 78 fb a5 a4 0f 22 c1 c6 45 f0 eb c6 45 f1 f9 eb 08 2b d8}  //weight: 2, accuracy: High
        $x_1_6 = "PsSetLoadImageNotifyRoutine" ascii //weight: 1
        $x_1_7 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Pasich_B_2147607768_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Pasich.B"
        threat_id = "2147607768"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Pasich"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 31 30 44 54 6a 30 6a 00 ff 15 ?? ?? ?? ?? 89 45 fc 83 7d fc 00 75 07}  //weight: 1, accuracy: Low
        $x_1_2 = {57 8d 7d f1 c6 45 f0 e9 ab 8b 7d 08 57 e8 ?? ?? 00 00 89 45 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Pasich_C_2147624113_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Pasich.C"
        threat_id = "2147624113"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Pasich"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {68 4f 63 70 70 ff 75 08 6a 00 ff 15}  //weight: 4, accuracy: High
        $x_4_2 = {68 4f 63 50 45 6a 0c 6a 00 ff 15}  //weight: 4, accuracy: High
        $x_1_3 = {0f 22 c0 fb 8b 45 08 8b 00 c6 00 e9 8b 45 08 8b 4d 08 8b 40 04 2b 01 83 e8 05}  //weight: 1, accuracy: High
        $x_1_4 = {c1 c2 03 32 10 40 80 38 00 75 f5}  //weight: 1, accuracy: High
        $x_1_5 = "current_ip" ascii //weight: 1
        $x_1_6 = "first_download_delay" ascii //weight: 1
        $x_1_7 = "last_download_time" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

