rule TrojanDownloader_Win32_Caxnet_B_2147628721_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Caxnet.B"
        threat_id = "2147628721"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Caxnet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/sports/image.jpg" ascii //weight: 1
        $x_1_2 = "/news/image.jpg" ascii //weight: 1
        $x_1_3 = "/files/image.jpg" ascii //weight: 1
        $x_1_4 = "/nba/image.jpg" ascii //weight: 1
        $x_1_5 = {70 69 6e 67 [0-6] 31 32 37 2e 30 2e 30 2e 31 3e 6e 75 6c}  //weight: 1, accuracy: Low
        $x_1_6 = "InternetOpenUrlA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

