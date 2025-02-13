rule Trojan_AndroidOS_Kolar_BD_2147744795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Kolar.BD!MTB"
        threat_id = "2147744795"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Kolar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Abrab16.0" ascii //weight: 1
        $x_1_2 = "WodkTiva" ascii //weight: 1
        $x_1_3 = "admsurprises" ascii //weight: 1
        $x_1_4 = "Azabelerina" ascii //weight: 1
        $x_1_5 = "BieActo." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

