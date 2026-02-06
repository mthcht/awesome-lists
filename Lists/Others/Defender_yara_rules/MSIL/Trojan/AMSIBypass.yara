rule Trojan_MSIL_AMSIBypass_AHB_2147962554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AMSIBypass.AHB!MTB"
        threat_id = "2147962554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AMSIBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "90"
        strings_accuracy = "Low"
    strings:
        $x_40_1 = {07 08 06 08 9a 28 ?? ?? ?? 0a 03 5b d2 9c 08 17 58 0c 08 07 8e 69 32 e8}  //weight: 40, accuracy: Low
        $x_30_2 = "ApplyEventTracingAdjustments" ascii //weight: 30
        $x_20_3 = "ApplySecurityAdjustments" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

