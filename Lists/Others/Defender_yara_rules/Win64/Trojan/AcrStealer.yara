rule Trojan_Win64_AcrStealer_FN_2147980810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AcrStealer.FN!MTB"
        threat_id = "2147980810"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AcrStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f0 24 88 05}  //weight: 1, accuracy: High
        $x_2_2 = {83 e8 01 0f b6 04 02 0f b6 12 01 d0}  //weight: 2, accuracy: High
        $x_1_3 = "ChromeUpdateMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

