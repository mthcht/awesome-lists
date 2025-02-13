rule TrojanDownloader_Win32_Dadon_A_2147639875_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dadon.A"
        threat_id = "2147639875"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dadon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "N@FFBAFFBAFFFAFFLEFFIDFFIDFF" wide //weight: 1
        $x_1_2 = "DeleteUrlCacheEntry" ascii //weight: 1
        $x_1_3 = "sniff" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

