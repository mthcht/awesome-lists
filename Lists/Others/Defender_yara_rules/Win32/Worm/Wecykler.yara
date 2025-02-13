rule Worm_Win32_Wecykler_A_2147665943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wecykler.A"
        threat_id = "2147665943"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wecykler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YU*.*2*/.*.63-1-563.*4/2012210*5062//..2*.--0" wide //weight: 1
        $x_1_2 = "Plcqt^obYJf`olplcqYTfkaltpY@roobkqSbopflkYOrk" wide //weight: 1
        $x_1_3 = {68 d0 07 00 00 57 ff d5 6a 00 6a 00 68 d0 07 00 00 53 ff d5 6a 00 8d 4c 24 18 51 68 de 01 00 00 56 57 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {66 8b 08 66 3b 0c 10 0f 85 8f 07 00 00 8b 4c 24 20 83 c1 01 83 c0 02 81 f9 ef 00 00 00 89 4c 24 20 7e dd}  //weight: 1, accuracy: High
        $x_1_5 = {66 8b 08 83 c0 02 66 85 c9 75 f5 2b c6 d1 f8 83 c0 ff 3b d0 76 da 8b 74 24 14 8d 4c 24 18 51 68}  //weight: 1, accuracy: High
        $x_1_6 = {8d 50 02 66 8b 08 83 c0 02 66 85 c9 75 f5 2b c2 d1 f8 8b d0 8d 4a 5a 3b d1 77 1a 2b ca 83 c1 01 d1 e9 8d 3c 53}  //weight: 1, accuracy: High
        $x_1_7 = {b8 4f ec c4 4e f7 e1 c1 ea 03 6b d2 e6 03 ca 83 c4 04 f6 c3 01 89 4c 24 04 75 05 83 c1 41 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

