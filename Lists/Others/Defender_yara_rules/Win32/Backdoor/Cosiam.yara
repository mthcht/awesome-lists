rule Backdoor_Win32_Cosiam_2147572218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cosiam"
        threat_id = "2147572218"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosiam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TheMatrixHasYou.exe" ascii //weight: 1
        $x_1_2 = "mini2tone.ini" ascii //weight: 1
        $x_1_3 = "MetaFollow" ascii //weight: 1
        $x_1_4 = "FollowRandHref" ascii //weight: 1
        $x_1_5 = "%s/l.php?un=%u" ascii //weight: 1
        $x_1_6 = "%s %u.%u %u %s" ascii //weight: 1
        $x_2_7 = {8d 7d f0 69 f6 98 03 00 00 ab ab ab ab 8b 86}  //weight: 2, accuracy: High
        $x_2_8 = {6a 20 69 c0 35 4e 5a 01 40 5b a3 ?? ?? 41 00 c1 e8 10 99 f7 fb 80 c2 41 38 54 31 ff 75 0a 8b c7}  //weight: 2, accuracy: Low
        $x_2_9 = {6a 0a 69 c0 35 4e 5a 01 40 33 d2 a3}  //weight: 2, accuracy: High
        $x_2_10 = {41 00 6a 3f 69 c0 35 4e 5a 01 40 59 a3}  //weight: 2, accuracy: High
        $x_2_11 = "890qwertyuiopasdfghjklz" ascii //weight: 2
        $x_3_12 = "dxvw%c%c%c%c.exe" ascii //weight: 3
        $x_3_13 = {74 17 8b 45 fc 69 c0 e8 03 00 00 99 f7 f9 33 d2 b9 e8 03 00 00 f7 f1 eb 05 b8 40 0d 03 00 5f}  //weight: 3, accuracy: High
        $x_3_14 = {41 00 6a 00 69 c0 35 4e 5a 01 40 6a 01 6a 3f a3 ?? ?? 41 00 c1 e8 10 33 d2 59 f7 f1 81 c2 ?? ?? 40 00 52 ff 75 08 ff 15 ?? ?? 40 00 83 f8 ff}  //weight: 3, accuracy: Low
        $x_3_15 = {0f 01 0f 8a 47 05 3c f7 74 11 3c f8 74 0d b1 d0 3a c8 1b c0 f7 d8 89 45 fc eb 05}  //weight: 3, accuracy: High
        $x_3_16 = {6a 00 8d 8d 70 fd ff ff 68 f4 01 00 00 51 50 ff 15 ?? ?? 40 00 6a 7d}  //weight: 3, accuracy: Low
        $x_3_17 = {83 c2 61 52 99 f7 fb 0f b7 c7 83 c2 61 52 53 99}  //weight: 3, accuracy: High
        $x_3_18 = {6a 07 33 c0 59 8d 7d d1 f3 ab 69 db 98 03 00 00 66 ab 66}  //weight: 3, accuracy: High
        $x_4_19 = {40 00 80 00 00 00 6a 0a bf ?? ?? 40 00 8d 75 d0 59 33 d2 f3 a6 75 0a c7 83 80 95 40 00 02 00 00 00 6a 0b bf}  //weight: 4, accuracy: Low
        $x_5_20 = {bf 0f 27 00 00 a1 ?? ?? 40 00 8b cf 69 c0 35 4e 5a 01 40 a3 ?? ?? 40 00 c1 e8 10 99 f7 f9 3b d7 89 15 ?? ?? 40 00 73 44 81 fa 05 0d}  //weight: 5, accuracy: Low
        $x_5_21 = "%s/r.php?i=%u&s=%u&o=%u&c=%u&v=%u&h=%u&l=%u&a=%u&ip=%s&win" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 6 of ($x_1_*))) or
            ((5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((3 of ($x_3_*) and 5 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 3 of ($x_2_*))) or
            ((4 of ($x_3_*) and 2 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_2_*))) or
            ((5 of ($x_3_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

