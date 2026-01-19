rule TrojanDownloader_Win64_Doina_ARAX_2147961295_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Doina.ARAX!MTB"
        threat_id = "2147961295"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\svchost_helper.exe" ascii //weight: 2
        $x_2_2 = "-DisableRealtimeMonitoring" ascii //weight: 2
        $x_2_3 = "update.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

