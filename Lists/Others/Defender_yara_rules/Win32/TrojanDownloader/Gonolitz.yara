rule TrojanDownloader_Win32_Gonolitz_A_2147647599_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Gonolitz.A"
        threat_id = "2147647599"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Gonolitz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Once survey is completed" ascii //weight: 1
        $x_1_2 = "File.rar" ascii //weight: 1
        $x_1_3 = "oligon downloader" ascii //weight: 1
        $x_1_4 = "freebests.com/time.htm" wide //weight: 1
        $x_1_5 = "bestlinkfree.com" wide //weight: 1
        $x_1_6 = "bn\\Bureau" wide //weight: 1
        $x_1_7 = "html2fpdf/font/makefont/files" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

