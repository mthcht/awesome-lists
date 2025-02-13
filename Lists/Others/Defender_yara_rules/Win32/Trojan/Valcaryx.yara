rule Trojan_Win32_Valcaryx_A_2147710824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valcaryx.A"
        threat_id = "2147710824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valcaryx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "/ys.8gys.com/new/" wide //weight: 4
        $x_3_2 = "www.appealzone.com/v4.php" wide //weight: 3
        $x_2_3 = "cavalryplayer" wide //weight: 2
        $x_2_4 = "PopupRecmd.exe" wide //weight: 2
        $x_3_5 = {61 00 63 00 74 00 3d 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 26 00 6f 00 70 00 3d 00 [0-24] 26 00 72 00 69 00 3d 00 25 00 73 00 26 00 6d 00 63 00 3d 00 25 00 73 00 26 00 76 00 73 00 3d 00 25 00 73 00 26 00 74 00 6d 00 3d 00 25 00 73 00 26 00 6f 00 73 00 3d 00 25 00 73 00 26 00 73 00 63 00 3d 00 25 00 73 00 26 00}  //weight: 3, accuracy: Low
        $x_1_6 = "vip.xinghuachun9.com/360" wide //weight: 1
        $x_1_7 = "0.cn/?src=lm&ls=n6e2b636997/" wide //weight: 1
        $x_1_8 = "(x86)\\jikai\\" ascii //weight: 1
        $x_1_9 = "\\cavalryplayerdlg.cpp" ascii //weight: 1
        $x_1_10 = "popupwndrestart" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Valcaryx_B_2147718542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valcaryx.B"
        threat_id = "2147718542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valcaryx"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 63 00 74 00 3d 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 26 00 6f 00 70 00 3d 00 [0-24] 26 00 72 00 69 00 3d 00 25 00 73 00 26 00 6d 00 63 00 3d 00 25 00 73 00 26 00 76 00 73 00 3d 00 25 00 73 00 26 00 74 00 6d 00 3d 00 25 00 73 00 26 00 6f 00 73 00 3d 00 25 00 73 00 26 00 73 00 63 00 3d 00 25 00 73 00 26 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/PopupRecmd.exe" wide //weight: 1
        $x_1_3 = "http://vip.fanyarightway.com/360/" wide //weight: 1
        $x_1_4 = {5c 00 74 00 61 00 73 00 73 00 6b 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00 00 00 5c 00 62 00 69 00 6e 00 64 00 65 00 78 00 65 00 31 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "\\Temp\\qibing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

