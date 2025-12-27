rule Trojan_Win32_Xmrig_NEAA_2147837433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xmrig.NEAA!MTB"
        threat_id = "2147837433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 4c 24 24 8b 74 24 34 8d 54 24 24 0f 43 4c 24 24 8b 7b 38 03 f1 83 7c 24 38 10 8d 4c 24 1c 51 0f 43 54 24 28 8d 4c 24 28 8b 07 51 8d 4c 24 2b 51 8d 4c 24 24 51 56 52 8d 4b 40 51 8b cf ff 50 18 83 e8 00}  //weight: 10, accuracy: High
        $x_2_2 = "uuaUHBaHB19aZ1" ascii //weight: 2
        $x_2_3 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\vbc.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xmrig_NEAB_2147838388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xmrig.NEAB!MTB"
        threat_id = "2147838388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 cc 83 c0 01 8b 4d d0 83 d1 00 89 45 cc 89 4d d0 83 7d d0 00 77 16 72 09 81 7d cc 00 e1 f5 05 73 0b 8b 55 d4 83 c2 01 89 55 d4 eb d2}  //weight: 5, accuracy: High
        $x_5_2 = {33 c5 89 45 fc 89 4d f4 8b 45 f4 89 45 e8 8b 4d 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xmrig_MA_2147843295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xmrig.MA!MTB"
        threat_id = "2147843295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 10 8b 44 24 24 01 44 24 10 8b d6 c1 ea 05 03 54 24 28 8d 04 37 31 44 24 10 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 14 8b 44 24 14 31 44 24 10 8b 44 24 10 29 44 24 18 81 c7 ?? ?? ?? ?? 4d 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xmrig_A_2147845229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xmrig.A!MTB"
        threat_id = "2147845229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f9 8b 45 08 0f be 04 10 69 c0}  //weight: 2, accuracy: High
        $x_2_2 = {08 33 ca 8b ?? 0c 03 ?? dc 88 0a eb 08 00 8b ?? 0c 03 ?? dc 0f b6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xmrig_AX_2147896816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xmrig.AX!MTB"
        threat_id = "2147896816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7b 00 c7 84 24 ?? ?? ?? ?? 56 b5 8b 2c c7 84 24 ?? ?? ?? ?? e1 c3 9c 0c c7 84 24 ?? ?? ?? ?? 94 27 73 51 c7 84 24 ?? ?? ?? ?? 65 48 6d 5a c7 84 24 ?? ?? ?? ?? 9f 3a 12 51 c7 84 24 ?? ?? ?? ?? 84 82 10 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Xmrig_ARAX_2147956835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xmrig.ARAX!MTB"
        threat_id = "2147956835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 46 10 8d 04 45 02 00 00 00 50 51 6a 01 6a 00 52 ff b5 ?? ff ff ff ff 15 08 20 41 00}  //weight: 2, accuracy: Low
        $x_2_2 = "\\updater.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

