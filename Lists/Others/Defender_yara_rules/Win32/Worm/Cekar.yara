rule Worm_Win32_Cekar_B_2147617542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cekar.B"
        threat_id = "2147617542"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cekar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 00 69 69 69 2e 83 c0 04 c7 00 65 78 65 00 6a 00 6a 00 6a 02 6a 00 6a 00 68 00 00 00 40 52 ff 55 14 89 45 44 3d ff ff ff ff 74 78}  //weight: 1, accuracy: High
        $x_1_2 = {01 ee b8 47 65 74 50 39 06 75 f1 b8 72 6f 63 41 39 46 04 75 e7 8b 5a 24 01 eb 66 8b 0c 4b 8b 5a 1c 01 eb 8b 04 8b 01 e8 55 83 ec 50 89 e5 89 45 10 68 6c 6f 63 00 68 61 6c 41 6c 68 47 6c 6f 62 54 57 ff 55 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

