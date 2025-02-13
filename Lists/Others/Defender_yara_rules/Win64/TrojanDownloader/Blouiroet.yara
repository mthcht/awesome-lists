rule TrojanDownloader_Win64_Blouiroet_SK_2147902957_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Blouiroet.SK!MTB"
        threat_id = "2147902957"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Blouiroet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c:\\programdata\\temp6.exe" ascii //weight: 2
        $x_2_2 = "http://winhost.xyz/update/update.rar" ascii //weight: 2
        $x_2_3 = "http://fontdrvhost.xyz/update/test5.rar" ascii //weight: 2
        $x_1_4 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_5 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

