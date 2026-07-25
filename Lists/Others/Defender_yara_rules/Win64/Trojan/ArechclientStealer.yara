rule Trojan_Win64_ArechclientStealer_Z_2147974532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ArechclientStealer.Z!MTB"
        threat_id = "2147974532"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ArechclientStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StealerSettingConfigParceT" ascii //weight: 1
        $x_1_2 = "get_telegram" ascii //weight: 1
        $x_1_3 = "set_discord" ascii //weight: 1
        $x_1_4 = "ScanWallets" ascii //weight: 1
        $x_1_5 = "set_ScanDiscord" ascii //weight: 1
        $x_1_6 = "ScanBrowsers" ascii //weight: 1
        $x_1_7 = "set_Username" ascii //weight: 1
        $x_1_8 = "set_Password" ascii //weight: 1
        $x_1_9 = "DownloadData" ascii //weight: 1
        $x_1_10 = "set_Hardware" ascii //weight: 1
        $x_1_11 = "set_MachineName" ascii //weight: 1
        $x_1_12 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

