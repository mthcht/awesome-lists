rule TrojanDownloader_Win32_Ragotav_A_2147697348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ragotav.A"
        threat_id = "2147697348"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ragotav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\loader2015\\loader2015\\Project1.vbp" wide //weight: 1
        $x_1_2 = {72 6f 64 61 6e 64 6f 00 63 6f 6e 66 69 67 75 72 61 72 00 00 6f 63 6f 6e 74 61 32 00 6f 63 6f 6e 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

