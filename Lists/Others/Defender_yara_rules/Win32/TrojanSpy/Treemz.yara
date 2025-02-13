rule TrojanSpy_Win32_Treemz_A_2147608696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Treemz.gen!A"
        threat_id = "2147608696"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Treemz"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {84 d2 74 0f 8b c8 80 f2 ?? 88 11 8a 51 01 41 84 d2 75 f3}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 51 01 41 84 d2 75 ?? 5d c3 03 00 80 31}  //weight: 1, accuracy: Low
        $x_1_3 = {85 c0 7e 09 80 34 31 ?? 41 3b c8 7c f7}  //weight: 1, accuracy: Low
        $x_1_4 = {7e 0c 80 34 1f ?? 53 47 ff d6 3b f8 7c f4}  //weight: 1, accuracy: Low
        $x_2_5 = {8d 45 f8 c6 45 f8 e9 50 56 68 ?? ?? ?? ?? 88 5d f9 88 5d fa 88 5d fb 88 5d fc}  //weight: 2, accuracy: Low
        $x_2_6 = {57 50 6a 02 ff 15 ?? ?? ?? ?? 85 c0 75 (5b|57) ff 75 08 ff 15 ?? ?? ?? ?? 6a 00 6a 01 6a 02 8b f0 ff 15}  //weight: 2, accuracy: Low
        $x_2_7 = {03 ce 8a 84 85 f4 fb ff ff 30 01 46 81 fe 80 00 00 00 (72|7c)}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

