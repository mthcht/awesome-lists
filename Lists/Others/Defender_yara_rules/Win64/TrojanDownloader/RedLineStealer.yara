rule TrojanDownloader_Win64_RedLineStealer_A_2147891364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/RedLineStealer.A!MTB"
        threat_id = "2147891364"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" wide //weight: 2
        $x_2_2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" wide //weight: 2
        $x_2_3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection" wide //weight: 2
        $x_2_4 = "TamperProtection" wide //weight: 2
        $x_2_5 = "DisableAntiSpyware" wide //weight: 2
        $x_2_6 = "DisableBehaviorMonitoring" wide //weight: 2
        $x_2_7 = "DisableOnAccessProtection" wide //weight: 2
        $x_2_8 = "DisableScanOnRealtimeEnable" wide //weight: 2
        $x_2_9 = ".xsph.ru/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

