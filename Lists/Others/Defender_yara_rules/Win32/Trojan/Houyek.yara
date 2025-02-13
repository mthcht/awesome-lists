rule Trojan_Win32_Houyek_A_2147645688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Houyek.A"
        threat_id = "2147645688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Houyek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 52 65 63 65 69 76 65 72 20 4c 61 73 74 20 4e 61 6d 65 3a}  //weight: 1, accuracy: High
        $x_1_2 = {3c 2f 63 69 74 79 3e 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 00 8b 40 30 50 e8 ?? ?? ?? ?? 8d 45 fc 50 6a 1a 8b c3 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 85 ?? fe ff ff 50 8b 45 fc 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

