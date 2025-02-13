rule Worm_Win32_Muzkas_A_2147649349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Muzkas.A"
        threat_id = "2147649349"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Muzkas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f0 8b d3 8b c6 8b 08 ff 51 08 c6 46 3f 28}  //weight: 2, accuracy: High
        $x_2_2 = {32 1c 08 8b 4c 24 04 88 1c 31 46 4a 75 b4}  //weight: 2, accuracy: High
        $x_2_3 = {ff 75 fc ff 75 f8 e8 ?? ?? ?? ff 8b d8 68 00 01 00 00 8d 85 f8 fe ff ff 50 53 e8 ?? ?? ?? ff 84 c0 74 2e}  //weight: 2, accuracy: Low
        $x_1_4 = "kull_name=" ascii //weight: 1
        $x_1_5 = "SunJavaUpdateSched.lnk" ascii //weight: 1
        $x_1_6 = "javascheds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Muzkas_B_2147655988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Muzkas.B"
        threat_id = "2147655988"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Muzkas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 fa 04 72 12 8b 5c 02 fc 0f cb c1 c3 04 89 5c 02 fc 83 ea 04 eb e9}  //weight: 1, accuracy: High
        $x_1_2 = {74 b7 46 54 56 f6 27 96 15 36 47 26 46 57 46 17}  //weight: 1, accuracy: High
        $x_1_3 = {74 c7 46 54 f6 36 96 76 17 24 46 c6 97 36 57 66}  //weight: 1, accuracy: High
        $x_1_4 = {96 57 46 e4 27 46 56 e7 f6 e6 57 04 54 16 c7 25}  //weight: 1, accuracy: High
        $x_1_5 = {37 46 66 f5 76 57 26 17 c6 36 94 d5 26 f7 36 f7 64 95 c7 46 e7 26 57 46 e2 07 46 56 56 c7 07 84 f7 26 57 26 00 00 00 00 55 8b ec 6a 00 53 8b d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

