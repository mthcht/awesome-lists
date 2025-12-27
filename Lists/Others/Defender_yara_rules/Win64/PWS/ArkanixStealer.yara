rule PWS_Win64_ArkanixStealer_CI_2147959183_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win64/ArkanixStealer.CI!MTB"
        threat_id = "2147959183"
        type = "PWS"
        platform = "Win64: Windows 64-bit platform"
        family = "ArkanixStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ArkanixStealer" ascii //weight: 2
        $x_2_2 = "Browser:" ascii //weight: 2
        $x_2_3 = "cookies.txt" ascii //weight: 2
        $x_2_4 = "autofills.txt" ascii //weight: 2
        $x_2_5 = "credit_cards.txt" ascii //weight: 2
        $x_2_6 = "Steam" ascii //weight: 2
        $x_2_7 = "/api/upload/direct" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

