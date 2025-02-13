rule Backdoor_MSIL_Warhawk_PAFQ_2147925990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Warhawk.PAFQ!MTB"
        threat_id = "2147925990"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Warhawk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 06 8f ?? ?? ?? ?? 25 47 11 04 11 06 1f 10 5d 91 61 d2 52 11 06 17 58 13 06 11 06 11 05 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

