rule Trojan_MSIL_RisePro_KAB_2147902685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RisePro.KAB!MTB"
        threat_id = "2147902685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 30 61 d2 81 ?? 00 00 01 03 50 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RisePro_RDD_2147919180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RisePro.RDD!MTB"
        threat_id = "2147919180"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RisePro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c9b8e46d-28da-437d-a789-205be954ae20" ascii //weight: 2
        $x_1_2 = "Botsoft" ascii //weight: 1
        $x_1_3 = "KLCP Update 18.5.0 Setup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

