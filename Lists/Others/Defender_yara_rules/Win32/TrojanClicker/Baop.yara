rule TrojanClicker_Win32_Baop_A_2147655735_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Baop.A"
        threat_id = "2147655735"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Baop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoClickBaidu" ascii //weight: 1
        $x_1_2 = "/db/banben.xml" wide //weight: 1
        $x_1_3 = "/db/config.xml" wide //weight: 1
        $x_1_4 = "<taskurl>/soft/sx298_task.aspx</taskurl>" wide //weight: 1
        $x_1_5 = "<regediturl>/soft/html/zhuce.aspx</regediturl>" wide //weight: 1
        $x_5_6 = {5c 00 63 00 6c 00 69 00 63 00 6b 00 74 00 69 00 6d 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 0c 00 00 00 2f 00 75 00 70 00 74 00 6d 00 70 00 00 00 00 00 22 00 00 00 2f 00 75 00 70 00 74 00 6d 00 70 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_5_7 = {54 00 65 00 73 00 74 00 42 00 61 00 6e 00 42 00 65 00 6e 00 00 00 00 00 18 00 00 00 44 00 6f 00 77 00 6e 00 4c 00 6f 00 61 00 64 00 54 00 61 00 73 00 6b 00 00 00 00 00 10 00 00 00 4e 00 65 00 78 00 74 00 54 00 61 00 73 00 6b 00 00 00 00 00}  //weight: 5, accuracy: High
        $x_5_8 = {75 00 72 00 6c 00 00 00 3a 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 62 00 61 00 69 00 64 00 75 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 73 00 65 00 6f 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 5 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

