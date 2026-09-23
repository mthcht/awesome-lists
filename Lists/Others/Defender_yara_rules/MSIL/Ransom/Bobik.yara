rule Ransom_MSIL_Bobik_MY_2147978643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Bobik.MY!MTB"
        threat_id = "2147978643"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransom_attack.gif" ascii //weight: 1
        $x_1_2 = "01011001A90HACKX7F20D9A4C6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

