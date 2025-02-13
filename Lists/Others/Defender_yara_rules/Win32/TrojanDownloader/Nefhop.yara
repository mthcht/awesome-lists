rule TrojanDownloader_Win32_Nefhop_A_2147696258_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nefhop.A"
        threat_id = "2147696258"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nefhop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 33 34 35 68 61 6f 7a 69 70 5f 6b [0-8] 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_1_2 = "jifen_2345" ascii //weight: 1
        $x_1_3 = "C:\\1ini" ascii //weight: 1
        $x_1_4 = "http://www.2345.com" ascii //weight: 1
        $x_1_5 = "D:\\dream\\win1.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

