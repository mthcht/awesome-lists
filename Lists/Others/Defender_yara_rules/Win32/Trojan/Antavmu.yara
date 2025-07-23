rule Trojan_Win32_Antavmu_GFS_2147809830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antavmu.GFS!MTB"
        threat_id = "2147809830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antavmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 74 24 58 8b 4f 54 55 8b 7e 3c 03 cf 8b f8 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8b 4c 24 5c}  //weight: 10, accuracy: High
        $x_10_2 = {8b d8 8b 44 24 48 33 d2 83 c4 0c 8b 48 04 8b 00 89 4c 24 0c c7 44 24 08 00 00 00 00 66 8b 50 14 66 83 78 06 00 8d 6c 02 18 0f 86 99 00 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Antavmu_GDT_2147839502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antavmu.GDT!MTB"
        threat_id = "2147839502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antavmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 45 ef 8b 4d 08 0f b6 11 33 d0 8b 45 08 88 10 0f b6 4d ef 8b 55 08 0f b6 02 03 c1 8b 4d 08 88 01 8b 55 08 83 c2 01 89 55 08}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Antavmu_GMA_2147900250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antavmu.GMA!MTB"
        threat_id = "2147900250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antavmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 57 c9 66 0f f8 c8 0f 11 89 ?? ?? ?? ?? 0f 10 81 ?? ?? ?? ?? 0f 57 c9 66 0f f8 c8 0f 11 89 ?? ?? ?? ?? 83 c1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Antavmu_MR_2147947199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antavmu.MR!MTB"
        threat_id = "2147947199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antavmu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 c9 31 d2 89 d0 89 d5 8b 9c 24 8c 00 00 00 83 e0 3f 83 c2 01 c1 fd 02 0f af c5 31 c8 83 c1 0d 01 d8 81 fa f4 01}  //weight: 10, accuracy: High
        $x_5_2 = {89 d7 09 c7 85 f2 0f 95 44 24 03 85 ea 0f 95 c3 38 5c 24 03 0f 45 c7 01 d2 83 e9 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

