rule PWS_Win32_Populf_B_2147596943_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Populf.B"
        threat_id = "2147596943"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Populf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 01 00 00 00 e8 98 ee ff ff 8b 55 e8 b8 a8 cc 40 00 b9 38 a1 40 00 e8 de a0 ff ff 8d 55 e4 b8 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Populf_B_2147596944_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Populf.B!dll"
        threat_id = "2147596944"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Populf"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 12 01 00 00 50 e8 63 0c fd ff 6a 00 68 5c 62 43 00 e8 b7 0b fd ff 85 c0 74 0d 6a 00 68 b4 5f 43 00 50 e8 86 0b fd ff 5d c2 14 00 00 00 41 56 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Populf_C_2147596945_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Populf.C"
        threat_id = "2147596945"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Populf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 01 00 00 00 e8 41 ef ff ff 8b 55 ec b8 68 bc 40 00 b9 e0 9d 40 00 e8 67 a5 ff ff 8d 55 e8 b8 01 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Populf_C_2147596946_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Populf.C!dll"
        threat_id = "2147596946"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Populf"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 6a 00 6a 00 6a 00 8b 45 fc e8 ?? ?? fc ff 50 8d 45 98 e8 48 fe ff ff 8b 45 98 e8 ?? ?? fc ff 50 8b 45 f4 50 e8 ?? ?? fd ff}  //weight: 1, accuracy: Low
        $x_1_2 = {fd ff b9 01 00 00 00 33 d2 b8 02 00 00 00 e8 c9 fe ff ff 33 c9 33 d2 b8 04 00 00 00 e8 bb fe ff ff 83 3d ?? ?? 43 00 03 74 0e 83 3d ?? ?? 43 00 01 74 05 e8 64 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule PWS_Win32_Populf_D_2147596947_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Populf.D"
        threat_id = "2147596947"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Populf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 e8 79 f2 ff ff 8b 55 ec b8 58 bc 40 00 b9 ?? 97 40 00 e8 1b a9 ff ff 8d 55 e8 b8 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Populf_D_2147596948_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Populf.D!dll"
        threat_id = "2147596948"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Populf"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fd ff b9 01 00 00 00 33 d2 b8 02 00 00 00 e8 c3 fe ff ff 33 c9 33 d2 b8 04 00 00 00 e8 b5 fe ff ff e8 70 fe ff ff eb 0a 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Populf_E_2147612791_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Populf.E!dll"
        threat_id = "2147612791"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Populf"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 12 6a 00 68 60 f0 00 00 68 12 01 00 00 50 e8 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 12 6a 00 68 60 f0 00 00 68 12 01 00 00 50 e8 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {66 3d 01 80 0f 85 ?? ?? 00 00 33 c0 8a c3 83 c0 f8 3d d6 00 00 00 0f 87}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

