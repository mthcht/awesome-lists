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

