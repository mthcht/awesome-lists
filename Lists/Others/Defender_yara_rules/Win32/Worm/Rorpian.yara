rule Worm_Win32_Rorpian_A_160583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rorpian.gen!A"
        threat_id = "160583"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rorpian"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 79 70 6f 72 6e 6f 2e 61 76 69 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 6f 72 6e 6d 6f 76 73 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_2_3 = {73 65 74 75 70 25 75 2e 66 6f 6e 00}  //weight: 2, accuracy: High
        $x_1_4 = {61 66 66 5f 25 75 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {73 65 74 75 70 25 75 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_3_6 = {53 ff d7 33 d2 6a 19 59 f7 f1 8b 45 08 8b 4d fc 80 c2 61 ff 45 fc 88 14 01 8d 46 01 39 45 fc}  //weight: 3, accuracy: High
        $x_1_7 = {8a 10 40 84 d2 75 ?? 2b c1 83 c0 5c 83 7d 7c 00 68 04 01 00 00}  //weight: 1, accuracy: Low
        $x_1_8 = "Sending exploit to %s from %s" ascii //weight: 1
        $x_1_9 = "downloadedav" ascii //weight: 1
        $x_1_10 = {05 00 00 03 10 00 00 00 [0-2] 00 00 01 00 00 00 [0-2] 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

