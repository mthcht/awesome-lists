rule Worm_Win32_Skypii_A_2147679359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Skypii.A"
        threat_id = "2147679359"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Skypii"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 74 00 53 00 6b 00 4d 00 61 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 2e 00 55 00 6e 00 69 00 63 00 6f 00 64 00 65 00 43 00 6c 00 61 00 73 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 09 68 00 01 00 00 52 ff d7 6a ?? ff d6 6a 00 6a 02 6a 00 6a 10 ff d3 6a ?? ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

