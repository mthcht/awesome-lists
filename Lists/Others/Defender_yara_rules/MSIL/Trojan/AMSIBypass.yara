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

rule Trojan_MSIL_AMSIBypass_AHC_2147963109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AMSIBypass.AHC!MTB"
        threat_id = "2147963109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AMSIBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "ApplyEventTracingAdjustments" ascii //weight: 5
        $x_10_2 = "ApplySecurityAdjustments" ascii //weight: 10
        $x_15_3 = "Skype{A8483C01-E840-4A8D-83F5-9AC0C3880390bb-BBD916912398811}" ascii //weight: 15
        $x_30_4 = {11 1a 91 fe 01 16 fe 01 13 1b 11 1b 2c 0b 72 ?? ?? ?? 70 73 ?? ?? ?? 0a 7a 00 11 1a 17 58 13 1a 11 1a 11 0f 8e 69 fe 04 13 1c 11 1c 2d c1}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_30_*))) or
            (all of ($x*))
        )
}

