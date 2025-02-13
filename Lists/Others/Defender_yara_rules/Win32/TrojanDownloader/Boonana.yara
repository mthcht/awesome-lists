rule TrojanDownloader_Win32_Boonana_A_2147639766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Boonana.A"
        threat_id = "2147639766"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Boonana"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "VFXDSys Compatibility" wide //weight: 10
        $x_1_2 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; GTB6.4; .NET CLR 2.0.50727" wide //weight: 1
        $x_1_3 = {6a 01 f3 a5 6a 02 68 10 01 00 00 68 ff 01 0f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

