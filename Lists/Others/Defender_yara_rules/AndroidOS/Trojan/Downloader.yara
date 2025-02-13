rule Trojan_AndroidOS_Downloader_A_2147750000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Downloader.A!MTB"
        threat_id = "2147750000"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/example/decoy/AccesbilityService;" ascii //weight: 1
        $x_1_2 = "com.abdulrauf.filemanager" ascii //weight: 1
        $x_1_3 = "/OverlayService;" ascii //weight: 1
        $x_1_4 = "ZGFsdmlrLnN5c3RlbS5EZXhDbGFzc0xvYWRlcg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

