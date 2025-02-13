rule Trojan_MSIL_Heracle_KAG_2147897090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracle.KAG!MTB"
        threat_id = "2147897090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 2b 06 20 ?? ?? ?? ?? 25 26 08 20 ?? ?? ?? ?? 5a 61 2b a4 07 16 31 08}  //weight: 5, accuracy: Low
        $x_1_2 = "kgwurhmajkdoezp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracle_KAH_2147897091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracle.KAH!MTB"
        threat_id = "2147897091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 05 08 11 05 91 07 11 04 93 28 ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 05 17 58 13 05 11 05 08 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

