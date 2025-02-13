rule TrojanDownloader_Win64_Razy_ARA_2147900139_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Razy.ARA!MTB"
        threat_id = "2147900139"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "001/puppet.Txt" ascii //weight: 2
        $x_2_2 = "/WowOpO.TXT?%d" ascii //weight: 2
        $x_2_3 = "DownloadFile" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

