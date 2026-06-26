rule TrojanDownloader_MSIL_TinyRCT_A_2147972425_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/TinyRCT.A!AMTB"
        threat_id = "2147972425"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TinyRCT"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://139.180.134.221/PerfWatson2.exe" ascii //weight: 3
        $x_1_2 = "c2NodGFza3MuZXhl" ascii //weight: 1
        $x_1_3 = "IC9zYyBvbmxvZ29uIC9ybCBoaWdoZXN0" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

