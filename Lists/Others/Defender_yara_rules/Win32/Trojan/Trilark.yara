rule Trojan_Win32_Trilark_A_2147745293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trilark.A!dha"
        threat_id = "2147745293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trilark"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "__START_MYTEST_MARKuuuii__" wide //weight: 1
        $x_2_2 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 64 65 73 6b 74 6f 70 2e 72 33 75 00 00 00 00 72 62}  //weight: 2, accuracy: High
        $x_1_3 = {83 e9 08 d1 e9 03 fd 33 f6 85 c9 7e ?? 0f b7 44 72 08 8b e8 81 e5 00 f0 00 00 81 fd 00 30 00 00 75 ?? 8b 6c 24 10 25 ff 0f 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

