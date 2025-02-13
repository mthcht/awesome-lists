rule TrojanDownloader_Win32_Gwelog_A_2147652050_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gwelog.A"
        threat_id = "2147652050"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gwelog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 53 79 73 74 65 6d 43 61 63 68 65 2e 62 61 74 00 00 00 00 53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 65 67 69 73 74 72 79 20 44 72 69 76 65 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 74 66 6d 6f 6e 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {77 69 6e 6c 6f 67 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {77 69 6e 6c 6f 67 73 30 30 31 30 32 30 00}  //weight: 1, accuracy: High
        $x_1_5 = "attrib +r +s +h +a " ascii //weight: 1
        $x_1_6 = "&start=" wide //weight: 1
        $x_1_7 = "google.com.tr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

