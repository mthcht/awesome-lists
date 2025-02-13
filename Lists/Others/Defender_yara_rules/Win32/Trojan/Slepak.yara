rule Trojan_Win32_Slepak_DEA_2147761737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Slepak.DEA!MTB"
        threat_id = "2147761737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Slepak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 8a 44 24 14 2b f5 c0 e3 06 81 ee 11 d7 00 00 2a c3 8a d8 89 2d ?? ?? ?? ?? 88 1d}  //weight: 1, accuracy: Low
        $x_1_2 = {04 37 02 d8 8a c1 b1 34 f6 e9 8a ca f6 d9 2a c8 0f b7 45 fc 02 d9 8d 0c 30 81 f9 a8 00 00 00 75 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Slepak_DEB_2147762091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Slepak.DEB!MTB"
        threat_id = "2147762091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Slepak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 0f 46 d9 05 ac 1a 06 01 81 3d ?? ?? ?? ?? 73 0f 00 00 a3 ?? ?? ?? ?? 89 02 75 09 2b 3d ?? ?? ?? ?? 83 de 00 83 c2 04 83 6c 24 0c 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Slepak_DEC_2147762178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Slepak.DEC!MTB"
        threat_id = "2147762178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Slepak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c0 2b c1 05 c5 8f 00 00 03 c3 a3 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 80 c3 5c 02 da 02 da 88 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Slepak_DED_2147762833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Slepak.DED!MTB"
        threat_id = "2147762833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Slepak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 2c 0f b6 c0 66 2b c2 8b 54 24 28 66 2b c7 0f b7 c8 a1 ?? ?? ?? ?? 89 02 83 c2 04 8a 44 24 32 2a c1 89 54 24 28 8b 54 24 2c 04 5e ff 4c 24 24 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Slepak_MX_2147765070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Slepak.MX!MTB"
        threat_id = "2147765070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Slepak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 ef 0d 00 00 8b 37 66 2b d0 a1 ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? 81 c6 70 3b 07 01 33 d2 89 35 ?? ?? ?? ?? 3b 15 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

