rule Worm_Win32_Shup_A_2147688826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Shup.A"
        threat_id = "2147688826"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Shup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f2 ae f7 d1 2b f9 8b f7 8b d9 83 c9 ff 8b fa f2 ae 8b cb 4f c1 e9 02 f3 a5 8b cb 8d 94 24 0c 02 00 00 83 e1 03 f3 a4 8d 7c 24 0c 83 c9 ff f2 ae f7 d1}  //weight: 1, accuracy: High
        $x_1_2 = {83 c9 ff 33 c0 8d 54 24 0c f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 eb 2c 50 8d 4c 24 10 68 a0 66 41 00 51 e8 d3 7f 00 00 83 c4 0c eb 17 8b 53 08 52 50 8d 44 24 14}  //weight: 1, accuracy: High
        $x_1_3 = {53 55 56 57 8d 84 24 1c 01 00 00 33 f6 50 68 00 02 00 00 89 74 24 18 ff 15 3c 40 41 00 85 c0 0f 84 0f 01 00 00 8a 84 24 1c 01 00 00 84 c0 0f 84 00 01 00 00 8d 9c 34 1c 01 00 00 83 c9 ff 8b fb 33 c0 f2 ae f7 d1 49 8b e9 0f be 0b 51 45 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

