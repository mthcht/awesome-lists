rule TrojanDownloader_MSIL_PateBin_A_2147752765_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PateBin.A!MTB"
        threat_id = "2147752765"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PateBin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pastebin.com/raw/QGWjRMqL" wide //weight: 1
        $x_1_2 = "pastebin.com/raw/ipCEC0zc" wide //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

