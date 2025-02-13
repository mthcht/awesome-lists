rule Ransom_Win32_HelloKitty_SA_2147913046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/HelloKitty.SA"
        threat_id = "2147913046"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "HelloKitty"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 45 08 8b 75 f4 fe 85 f7 fd ff ff 0f 11 44 05 b4 83 c0 10 89 45 08 83 f8 30 7c 82}  //weight: 3, accuracy: High
        $x_3_2 = {81 c3 dc a9 b0 5c c1 c9 0b 33 c8 89 55 a0 8b c7 8b 7d e0 c1 c8 06 33 f7}  //weight: 3, accuracy: High
        $x_1_3 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 2c 01 01 09 30 2d 39 41 2d 5a 61 2d 7a 02 00 2c 01 01 09 30 2d 39 41 2d 5a 61 2d 7a}  //weight: 1, accuracy: Low
        $x_1_4 = {62 00 6f 00 6f 00 74 00 66 00 6f 00 6e 00 74 00 2e 00 62 00 69 00 6e 00 2c 01 01 09 30 2d 39 41 2d 5a 61 2d 7a 02 00 2c 01 01 09 30 2d 39 41 2d 5a 61 2d 7a}  //weight: 1, accuracy: Low
        $x_1_5 = {44 00 45 00 43 00 52 00 59 00 50 00 54 00 5f 00 4e 00 4f 00 54 00 45 00 2e 00 74 00 78 00 74 00 2c 01 01 09 30 2d 39 41 2d 5a 61 2d 7a 02 00 2c 01 01 09 30 2d 39 41 2d 5a 61 2d 7a}  //weight: 1, accuracy: Low
        $x_1_6 = ".onion" wide //weight: 1
        $x_1_7 = {8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 53 0f 11 45 ec}  //weight: 1, accuracy: High
        $x_1_8 = {56 57 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20}  //weight: 1, accuracy: High
        $x_1_9 = {57 8b f9 0f 57 c0 68 18 01 00 00 6a 00 0f 11 45 dc 8d 5f 20 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

