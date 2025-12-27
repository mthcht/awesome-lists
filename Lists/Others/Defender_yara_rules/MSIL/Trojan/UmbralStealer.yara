rule Trojan_MSIL_UmbralStealer_SG_2147904337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/UmbralStealer.SG!MTB"
        threat_id = "2147904337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "UmbralStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Umbral.payload.exe" ascii //weight: 1
        $x_1_2 = "Umbral Stealer Payload" ascii //weight: 1
        $x_1_3 = "$e823c15a-ddaf-4d1e-a6eb-80645d1ee735" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_UmbralStealer_ZCJ_2147958013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/UmbralStealer.ZCJ!MTB"
        threat_id = "2147958013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "UmbralStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 8e 69 8d ?? 00 00 01 0b 16 0c 2b 0f 00 07 08 06 08 91 03 61 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d e7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

