rule Trojan_MSIL_Saint_QLF_2147827983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Saint.QLF!MTB"
        threat_id = "2147827983"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Saint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 9a 28 ?? ?? ?? 0a 0d 09 18 5d 2d 0e 07 08 09 1f 19 58 28 ?? ?? ?? 0a 9c 2b 0c 07 08 09 1f 0f 59 28 ?? ?? ?? 0a 9c 08 17 58 0c 08 06 8e 69 17 59 32 cc}  //weight: 1, accuracy: Low
        $x_1_2 = "Split" ascii //weight: 1
        $x_1_3 = "hellobozo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

