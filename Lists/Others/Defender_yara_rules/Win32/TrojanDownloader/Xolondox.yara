rule TrojanDownloader_Win32_Xolondox_A_2147654036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Xolondox.A"
        threat_id = "2147654036"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Xolondox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 4c 58 4e 44 58 53 00 25 64 2e 67 69 66}  //weight: 1, accuracy: High
        $x_1_2 = "s\\Qedir\\*.*" ascii //weight: 1
        $x_1_3 = "%s?mac=%s&userid=%s&jinchengshu=%d" ascii //weight: 1
        $x_1_4 = "Files\\933.txt" ascii //weight: 1
        $x_1_5 = "grrhthtu76656" ascii //weight: 1
        $x_4_6 = {c6 45 a8 68 c6 45 a9 74 c6 45 aa 74 c6 45 ab 70 c6 45 ac 3a c6 45 ad 2f c6 45 ae 2f}  //weight: 4, accuracy: High
        $x_4_7 = {c6 45 d4 63 c6 45 d5 6f c6 45 d6 6e c6 45 d7 69 c6 45 d8 6d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

