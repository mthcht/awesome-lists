rule TrojanDownloader_MSIL_Adload_2147727854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Adload"
        threat_id = "2147727854"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Adload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://asedownloadgate.com/safe_download/582369/AdsShow.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

