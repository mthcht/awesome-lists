rule Trojan_Win32_Vbulla_A_2147630341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbulla.A"
        threat_id = "2147630341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbulla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 53 00 79 00 6d 00 61 00 6e 00 74 00 65 00 63 00 5c 00 4c 00 69 00 76 00 65 00 55 00 70 00 64 00 61 00 74 00 65 00 5c 00 4c 00 55 00 41 00 4c 00 4c 00 2e 00 45 00 58 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {2a 00 2e 00 6d 00 70 00 67 00 00 00 0a 00 00 00 2a 00 2e 00 61 00 76 00 69 00 00 00 0a 00 00 00 2a 00 2e 00 6a 00 70 00 67 00 00 00 0a 00 00 00 2a 00 2e 00 6d 00 70 00 33 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 fc 07 00 00 00 68 ?? ?? 40 00 8b 55 08 8b 42 70 50 ff 15 ?? ?? 40 00 c7 45 fc 08 00 00 00 ff 15 ?? ?? 40 00 d9 5d cc c7 45 c4 04 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

