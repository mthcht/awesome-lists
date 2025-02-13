rule Trojan_Win32_Wuprad_A_2147629902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wuprad.A"
        threat_id = "2147629902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wuprad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "zveryuga.com.ua" ascii //weight: 2
        $x_2_2 = "downcontroller/?affid=%s" ascii //weight: 2
        $x_2_3 = "downcontroller/mark.php" ascii //weight: 2
        $x_1_4 = {64 6f 77 6e 73 00 00 00 ff ff ff ff 01 00 00 00 3b 00 00 00 6d 61 73 74 00}  //weight: 1, accuracy: High
        $x_2_5 = {00 c2 cd c8 cc c0 cd c8 c5 21 20 c2 fb 03 00 44 00}  //weight: 2, accuracy: Low
        $x_1_6 = {6a 21 57 6a 01 53 68 ?? ?? ?? ?? 51 ff d6}  //weight: 1, accuracy: Low
        $x_1_7 = {83 f8 02 74 44 8b 04 24 8d 4c 24 04 51 8d 54 24 0c 52 6a 00 6a 00}  //weight: 1, accuracy: High
        $x_1_8 = {75 34 6a 00 8d 45 fc 50 68 0a 00 74 05 83 e8 04 8b 00 83 f8 20}  //weight: 1, accuracy: Low
        $x_1_9 = {ff d6 3d fd 2e 00 00 0f 84 ?? ?? ?? ?? ff d6 3d e7 2e 00 00 0f 84 ?? ?? ?? ?? 6a 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

