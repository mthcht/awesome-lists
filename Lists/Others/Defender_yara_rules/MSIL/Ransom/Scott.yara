rule Ransom_MSIL_Scott_DA_2147774386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Scott.DA!MTB"
        threat_id = "2147774386"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scott"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "scott rasom" ascii //weight: 1
        $x_1_2 = "i will will give you the password" ascii //weight: 1
        $x_1_3 = "i will destroy the key and you will never get it good luck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

