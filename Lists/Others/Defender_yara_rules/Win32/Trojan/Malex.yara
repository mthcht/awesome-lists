rule Trojan_Win32_Malex_ASG_2147917448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malex.ASG!MTB"
        threat_id = "2147917448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ba 02 00 00 00 8a 84 15 ?? ?? ff ff 84 c0 74 22 8a 8d ?? ?? ff ff 32 8d ?? ?? ff ff 80 c9 50 30 c1 88 8c 15 ?? ?? ff ff 42 eb}  //weight: 3, accuracy: Low
        $x_2_2 = {85 c0 89 85 ?? fb ff ff 19 c0 f7 d8 8d 85 ?? fb ff ff 6a 10 50 ff b5}  //weight: 2, accuracy: Low
        $x_1_3 = "{%04X-8B9A-11D5-EBA1-F78EEEEEE983}" ascii //weight: 1
        $x_1_4 = "%d processes killed OK" ascii //weight: 1
        $x_1_5 = "reboot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Malex_GNN_2147918723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malex.GNN!MTB"
        threat_id = "2147918723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {32 f6 44 24 08 10 75 0a 33 c0 5e}  //weight: 5, accuracy: High
        $x_5_2 = {8a 16 32 d0 88 16 46 8d 14 37 83 fa 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Malex_AMX_2147928584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malex.AMX!MTB"
        threat_id = "2147928584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 01 6a 10 68 94 7a 42 00 68 06 7c 42 00 e8 ?? ?? ?? ?? 83 c4 10 6a 01 6a 10 68 a5 7a 42 00 68 06 7c 42 00 e8 ?? ?? ?? ?? 83 c4 10 6a 01 6a 10 68 b6 7a 42 00 68 06 7c 42 00 e8 ?? ?? ?? ?? 83 c4 10 6a 01 6a 10 ff 35 e4 7a 42 00 68 06 7c 42 00 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {83 c4 1c ff 35 20 59 42 00 68 80 8d 42 00 68 28 9c 41 00 e8 ?? ?? ?? ?? 83 c4 0c 68 28 9c 41 00 68 a4 8d 42 00 68 30 97 41 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

