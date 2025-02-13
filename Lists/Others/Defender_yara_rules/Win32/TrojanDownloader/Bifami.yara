rule TrojanDownloader_Win32_Bifami_A_2147685938_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bifami.A"
        threat_id = "2147685938"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bifami"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sent Key 5K-HJ89ERd" wide //weight: 1
        $x_1_2 = "Sent Key G6k-33RBn2" wide //weight: 1
        $x_1_3 = "\\atieclx.vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

