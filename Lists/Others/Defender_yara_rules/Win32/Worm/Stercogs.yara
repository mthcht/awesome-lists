rule Worm_Win32_Stercogs_B_2147601308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Stercogs.B"
        threat_id = "2147601308"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Stercogs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 00 e1 40 00 8b 35 04 e2 40 00 6a 03 5f 89 45 ec 89 7d f0 8b 45 ec c7 45 fc 01 00 00 00 8b cf d3 65 fc 85 45 fc 74 76 83 c7 41 57 8d 45 d4 68 c0 e2 40 00 50 ff d6 83 c4 0c 8d 45 d4 50 ff 15 fc e0 40 00 83 f8 02 75 55 57 8d 45 a4 68 b8 e2 40 00 50 ff d6 83 c4 0c 33 c0 50 50 6a 03 50 6a 03 68 00 00 00 80 8d 45 a4 50 ff 15 60 e0 40 00 83 f8 ff 89 45 f8 74 26}  //weight: 1, accuracy: High
        $x_1_2 = {41 3a 00 00 46 41 54 00 46 41 54 33 32 00 00 00 25 63 3a 5c 25 73 00 00 5c 5c 3f 5c 25 63 3a 00 25 63 3a 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

