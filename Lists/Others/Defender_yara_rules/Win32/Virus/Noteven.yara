rule Virus_Win32_Noteven_A_2147681363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Noteven.A"
        threat_id = "2147681363"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Noteven"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 45 e4 50 6a 01 68 00 10 00 00 ff 75 e0 8b 45 b4 ff d0 61 89 45 e8 8a 07 3c e8 0f 84 ad 02 00 00 3c c3 0f 84 b1 03 00 00 3c ff 0f 84 f4 02 00 00 3c eb 74 67 3c e9 0f 84 82 00 00 00 3c 0f 0f 84 8b 00 00 00 24 f0 3c 70 0f 84 9a 00 00 00 3c e0 74 05 e9 bb 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

