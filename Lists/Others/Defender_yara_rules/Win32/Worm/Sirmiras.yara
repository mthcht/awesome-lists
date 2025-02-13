rule Worm_Win32_Sirmiras_A_2147611221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sirmiras.A"
        threat_id = "2147611221"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirmiras"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 3a ff 0f b7 ce c1 e9 08 32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 43 66 ff 4c 24 04 75 c5}  //weight: 2, accuracy: High
        $x_2_2 = {6a 00 6a 11 e8 ?? ?? ff ff 6a 00 6a 00 6a 00 6a 56 e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 6a 00 6a 03 6a 2d 6a 11 e8 ?? ?? ff ff 6a 00 6a 00 6a 00 6a 0d}  //weight: 2, accuracy: Low
        $x_2_3 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 2, accuracy: High
        $x_1_4 = {70 72 69 6e 63 65 73 73 5f 73 72 69 72 61 73 6d 69 2e 7a 69 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 72 65 61 6c 70 6c 61 79 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

