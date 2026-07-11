rule Trojan_MSIL_SentinelStealer_AHM_2147973339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SentinelStealer.AHM!MTB"
        threat_id = "2147973339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SentinelStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "SentinelStealerSource\\SentinelStealerSource" ascii //weight: 30
        $x_20_2 = "s\\\\.\\pipe\\SentinelPipe" ascii //weight: 20
        $x_1_3 = "chrome.exe" ascii //weight: 1
        $x_1_4 = "brave.exe" ascii //weight: 1
        $x_1_5 = "msedge.exe" ascii //weight: 1
        $x_1_6 = "avastbrowser.exe" ascii //weight: 1
        $x_1_7 = "Unknown browser process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

