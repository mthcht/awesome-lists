rule TrojanDownloader_Win64_Anonymous_EC_2147922601_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Anonymous.EC!MTB"
        threat_id = "2147922601"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Anonymous"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "lhgzkxk-1-1326101028.cos.ap-chengdu.myqcloud.com/ladhzjxa.png" ascii //weight: 5
        $x_1_2 = "DownloadAgent" ascii //weight: 1
        $x_1_3 = "InternetOpenA" ascii //weight: 1
        $x_1_4 = "%s\\2024.png" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_6 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

