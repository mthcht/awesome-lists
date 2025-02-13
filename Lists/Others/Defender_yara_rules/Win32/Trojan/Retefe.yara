rule Trojan_Win32_Retefe_A_2147685321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Retefe.A"
        threat_id = "2147685321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Retefe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 68 65 63 6b 54 6f 6b 65 6e 4d 65 6d 62 65 72 73 68 69 70 00 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {00 43 45 52 54 5f 49 6d 70 6f 72 74 43 65 72 74 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 51 04 8b 84 15 ?? ff ff ff a8 06 75 5b 8b 8c 15 ?? ff ff ff 8b 11 8b 52 28 6a 01 6a 02 56 56 8d 45 ?? 50 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

