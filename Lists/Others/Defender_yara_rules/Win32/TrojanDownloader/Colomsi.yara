rule TrojanDownloader_Win32_Colomsi_A_2147628324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Colomsi.A"
        threat_id = "2147628324"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Colomsi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CheaterCommunity" ascii //weight: 1
        $x_1_2 = "Projects\\ImSoCOOOOL" ascii //weight: 1
        $x_1_3 = "/geh-ins.kz/dl/wrar380d.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

