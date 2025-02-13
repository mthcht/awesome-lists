rule Trojan_Win32_Waldek_A_2147721442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waldek.A!bit"
        threat_id = "2147721442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waldek"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 0c c7 05 ?? ?? ?? ?? 01 00 00 00 eb 0a c7 05 ?? ?? ?? ?? 00 00 00 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 00 6a 02 50 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 0c 40 89 0d ?? ?? ?? ?? 85 c9 7e 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {57 8b f8 8b 4f 14 83 f9 10 72 02 8b 07 3d ?? ?? ?? ?? 77 35 83 f9 10 72 04 8b 07 eb 02 8b c7 8b 57 10 03 d0 81 fa ?? ?? ?? ?? 76 1d 83 f9 10 72 04 8b 07 eb 02 8b c7 b9 ?? ?? ?? ?? 2b c8 51 57 8b c3 e8 ?? ?? ?? ?? 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Waldek_VU_2147819668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waldek.VU!MTB"
        threat_id = "2147819668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waldek"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 55 d0 c1 e2 0b 89 55 d0 c6 45 ff 01 eb 42 c6 45 e7 01 c6 45 ef 01 8b 45 f8 c1 e0 dd 89 45 f8 c6 45 fe 01 8b 4d d0 81 f1 76 21 1b 00 89 4d d0 c6 45 cf 01 c6 45 e7 00 8b 55 f8 c1 fa 2b 89 55 f8 c6 45 ff 01 c6 45 ef 01}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Waldek_GKI_2147849670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waldek.GKI!MTB"
        threat_id = "2147849670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waldek"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 ca 0f b6 d3 0f af d1 02 14 33 43 32 c2 8b 54 24 ?? 83 fb ?? 7c ?? 88 04 3a 42 89 54 24 ?? 3b d5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

