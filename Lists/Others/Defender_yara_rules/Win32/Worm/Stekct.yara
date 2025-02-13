rule Worm_Win32_Stekct_A_170416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Stekct.A"
        threat_id = "170416"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Stekct"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "YahooBuddyMain" ascii //weight: 10
        $x_3_2 = "msg_id=%i&client_time=%i&to=%s" ascii //weight: 3
        $x_3_3 = {4d 73 4d 70 45 6e 67 2e 65 78 65 [0-32] 65 67 75 69 2e 65 78 65}  //weight: 3, accuracy: Low
        $x_1_4 = {6a 00 6a 00 6a 00 6a 25 ff d6 6a 00 6a 00 6a 00 6a 26 ff d6 33 d2 8b c5 b9 05 00 00 00 f7 f1 85 d2 75 04 6a 01 ff d7 45 81 fd ?? ?? 00 00 7c d0}  //weight: 1, accuracy: Low
        $x_1_5 = {53 53 53 6a 25 ff d6 53 53 53 6a 26 ff d6 8b 44 24 ?? 6a 05 99 59 f7 f9 85 d2 75 04 6a 01 ff d7 ff 44 24 ?? 81 7c 24 ?? ?? ?? 00 00 7c d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

