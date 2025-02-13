rule TrojanDownloader_Win32_Clikug_A_2147686057_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Clikug.A"
        threat_id = "2147686057"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7a 00 67 00 69 00 67 00 61 00 63 00 6c 00 69 00 63 00 6b 00 73 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = ".?AVCGigaClicksInfo@@" ascii //weight: 2
        $x_1_3 = ".?AVCTinyInstallerApp@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Clikug_A_2147686057_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Clikug.A"
        threat_id = "2147686057"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".?AVCOptimizerProInfo@@" ascii //weight: 1
        $x_1_2 = ".?AVCLolipopeFRInfo@@" ascii //weight: 1
        $x_1_3 = ".?AVCPCFixSpeedInfo@@" ascii //weight: 1
        $x_2_4 = ".?AVCGigaClicksInfo@@" ascii //weight: 2
        $x_1_5 = ".?AVCTinyInstallerApp@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Clikug_B_2147686134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Clikug.B"
        threat_id = "2147686134"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\GigaClicks Crawler" ascii //weight: 10
        $x_10_2 = "User-Agent: NSISDL/1.2 (Mozilla)" ascii //weight: 10
        $x_1_3 = "http://cdn.gigaclicks.net/file.php?supp=130" ascii //weight: 1
        $x_1_4 = "http://cdn.gigaclicks.net/file.php?supp=126" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Clikug_B_2147686134_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Clikug.B"
        threat_id = "2147686134"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Clikug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zidlecrawler" wide //weight: 1
        $x_1_2 = "IdlecrawlerControl" ascii //weight: 1
        $x_1_3 = "IdleCrawler country check:" wide //weight: 1
        $x_1_4 = "cdn.idlecrawler.com/precheck/?supp=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

