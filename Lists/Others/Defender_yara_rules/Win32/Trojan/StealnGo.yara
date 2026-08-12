rule Trojan_Win32_StealnGo_C_2147976076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StealnGo.C!MTB"
        threat_id = "2147976076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StealnGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CollectAndSendSystemInfo" ascii //weight: 5
        $x_5_2 = "api.telegram.org" wide //weight: 5
        $x_5_3 = "Running Processes:" wide //weight: 5
        $x_5_4 = "Info Collected:" wide //weight: 5
        $x_5_5 = "screenshot.png" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

