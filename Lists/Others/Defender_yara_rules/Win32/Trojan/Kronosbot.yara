rule Trojan_Win32_Kronosbot_RR_2147833670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kronosbot.RR!MTB"
        threat_id = "2147833670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kronosbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_url http*bbva*.mx* GP" ascii //weight: 1
        $x_1_2 = "data_inject" ascii //weight: 1
        $x_1_3 = "Y8{OtcWo@rFb[ag9KIjm]]W1WLR8qS8" ascii //weight: 1
        $x_1_4 = "CollectInfo" ascii //weight: 1
        $x_1_5 = "continuenumsync.ml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

