rule Worm_Win32_Pasnit_A_2147727039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pasnit.A"
        threat_id = "2147727039"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pasnit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 02 2e 00 44 00 33 c0 c7 42 04 4c 00 4c 00 66 89 42 08 8d 95 ?? ?? ff ff 66 8b 85 ?? ?? ff ff 56 33 f6 66 85 c0 74 ?? 0f b7 c0 66 83 f8 41 72 0e}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 17 8d 49 08 81 f2 ?? ?? ?? ?? 8d 7f 04 0f b6 c2 66 89 41 f8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 06 8d 76 04 35 ?? ?? ?? ?? 42 89 44 37 fc 3b d3 72 ed}  //weight: 1, accuracy: Low
        $x_2_4 = {83 7d f8 00 74 1c 6a 00 6a 04 8d 45 fc 50 8b 85 ?? ?? ff ff 05 ?? ?? ?? ?? 50 ff 36 ff 15 ?? ?? ?? ?? 8b 47 28 03 45 fc 89 85 ?? ?? ff ff 8d 85 ?? ?? ff ff 50 ff 76 04 ff 15}  //weight: 2, accuracy: Low
        $x_2_5 = {ff 30 48 83 e8 08 e2 f8 67 4c 8b 4d 30 67 4c 8b 45 28 67 48 8b 55 20 67 48 8b 4d 18 83 ec 20 41 ff d3}  //weight: 2, accuracy: High
        $x_2_6 = {25 00 73 00 c7 45 ?? 25 00 73 00 c7 45 ?? 5c 00 25 00 c7 45 ?? 75 00 2e 00 c7 45 ?? 65 00 78 00 c7 45 ?? 65 00 00 00 c7 85 ?? ff ff ff 22 00 25 00 c7 85 ?? ff ff ff 73 00 5c 00}  //weight: 2, accuracy: Low
        $x_1_7 = {83 f8 35 0f 84 ?? ?? 00 00 83 f8 43 0f 84 ?? ?? 00 00 3d e7 01 00 00 0f 84 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = {73 00 22 00 c7 45 ?? 20 00 2f 00 c7 45 ?? 73 00 74 00 c7 45 ?? 61 00 62 00 c7 45 ?? 20 00 22 00 c7 45 ?? 25 00 73 00 c7 45 ?? 22 00 00 00}  //weight: 1, accuracy: Low
        $x_1_9 = {73 00 74 00 c7 45 ?? 61 00 62 00 c7 45 ?? 20 00 22 00 c7 45 ?? 25 00 73 00 c7 45 ?? 22 00 00 00}  //weight: 1, accuracy: Low
        $x_1_10 = {74 0d 32 d0 69 d2 ?? ?? ?? ?? 49 ff c0 eb ec 67 3b 55 10 74 08 49 83 c1 04 ff c1 eb cd}  //weight: 1, accuracy: Low
        $x_1_11 = ",crazy,zxc123,alpha," ascii //weight: 1
        $x_1_12 = ",donkey,hooters,sniper," ascii //weight: 1
        $x_1_13 = ",mustang,123321,qwertyuiop," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

