rule Trojan_Win32_Hilasy_A_2147658509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hilasy.A"
        threat_id = "2147658509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hilasy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "aoiaQ0rhd" ascii //weight: 1
        $x_1_2 = {68 70 17 00 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 c3 07 00 c7 04 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hilasy_B_2147658510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hilasy.B"
        threat_id = "2147658510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hilasy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 61 00 73 00 79 00 6e 00 63 00 6c 00 61 00 79 00 65 00 72 00 62 00 6f 00 75 00 6e 00 64 00 61 00 72 00 79 00 64 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {3b c1 77 0f 51 89 47 ?? 56 83 c7 ?? 57 ff 15 ?? ?? ?? ?? 8b 45 ?? ff b0 ?? ?? 00 00 ff 15 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? 6a 02 05 00 b9 00 90 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hilasy_C_2147678972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hilasy.C"
        threat_id = "2147678972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hilasy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b c8 83 c4 1c 81 f9 00 10 00 00 0f 86 0d 01 00 00 80 38 4d 0f 85 04 01 00 00 80 78 01 5a}  //weight: 1, accuracy: High
        $x_1_2 = {74 2d 38 5e 04 75 28 8b 46 14 57 8b 7e 18 2b 7e 14 53 8d 4d f8 51 57 50 ff 75 fc ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

