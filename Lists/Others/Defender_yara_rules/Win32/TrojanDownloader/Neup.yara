rule TrojanDownloader_Win32_Neup_A_2147642276_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Neup.A"
        threat_id = "2147642276"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Neup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\sspi32.exe" ascii //weight: 2
        $x_2_2 = "%s\\newup.exe" ascii //weight: 2
        $x_2_3 = {53 68 65 6c 6c 00 00 00 45 78 65 63 75 00 00 00 74 65 41 00}  //weight: 2, accuracy: High
        $x_1_4 = {5c 69 65 76 65 72 73 69 6f 6e 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_5 = "//159sw.com/" ascii //weight: 1
        $x_1_6 = {00 67 67 5f 62 68 6f 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 67 67 5f 73 70 69 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

