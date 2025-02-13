rule Spammer_Win32_Sispotat_A_2147706916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Sispotat.A"
        threat_id = "2147706916"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Sispotat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 24 30 2d 70 77 00 ff 04 00 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 74 6f 00 04 00 c7}  //weight: 1, accuracy: Low
        $x_1_3 = {b8 1f 85 eb 51 f7 64 24 ?? c1 ea 05 83 fa 02}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 61 74 74 61 63 68 00 2d 73 75 62 6a 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {2d 74 6f 00 2d 70 72 69 6f 72 69 74 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {2d 70 77 00 2d 75 00 00 32 35 2d 70 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {25 5b 5e 27 2c 27 5d 2c 25 5b 5e 27 2c 27 5d 2c 25 5b 5e 27 2c 27 5d 2c 25 5b 5e 27 2c 27 5d 00}  //weight: 1, accuracy: High
        $x_1_8 = {2f 61 74 61 63 68 2f 61 74 61 63 68 2e 70 68 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

