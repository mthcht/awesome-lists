rule Trojan_MSIL_BigHead_A_2147978169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BigHead.A!MTB"
        threat_id = "2147978169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BigHead"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "=== STEAL [" wide //weight: 15
        $x_10_2 = "AmsiScanBuffer" wide //weight: 10
        $x_5_3 = "STEALOUT" wide //weight: 5
        $x_3_4 = "PatchAmsi" ascii //weight: 3
        $x_2_5 = "GrabCookiesCore" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

