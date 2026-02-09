rule Trojan_Win64_EvelynStealer_GVA_2147962676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EvelynStealer.GVA!MTB"
        threat_id = "2147962676"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EvelynStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WindowStyle Hidden" wide //weight: 1
        $x_2_2 = "://syn1112223334445556667778889990.org/" wide //weight: 2
        $x_1_3 = "Start-Process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

