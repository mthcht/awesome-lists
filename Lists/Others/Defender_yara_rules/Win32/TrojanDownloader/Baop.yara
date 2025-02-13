rule TrojanDownloader_Win32_Baop_A_2147655734_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Baop.A"
        threat_id = "2147655734"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Baop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WebBanben_OnReadyStateChange" ascii //weight: 1
        $x_1_2 = "oft/uplist.aspx?admin=" wide //weight: 1
        $x_1_3 = "/db/banben.xml" wide //weight: 1
        $x_1_4 = "/db/config.xml" wide //weight: 1
        $x_1_5 = "/uptmp/update.exe" wide //weight: 1
        $x_5_6 = {70 00 61 00 74 00 68 00 3d 00 00 00 [0-16] 26 00 73 00 74 00 61 00 72 00 74 00 3d 00 00 00}  //weight: 5, accuracy: Low
        $x_5_7 = "oft/down.aspx" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

