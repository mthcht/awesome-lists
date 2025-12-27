rule Ransom_MSIL_Lapsus_YAB_2147908019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Lapsus.YAB!MTB"
        threat_id = "2147908019"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lapsus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lapsus__Ransom" ascii //weight: 1
        $x_1_2 = "EncryptDirectory" ascii //weight: 1
        $x_1_3 = {02 28 4a 00 00 0a 0d 02 28 4b 00 00 0a 02 28 4c 00 00 0a 72 e6 08 00 70 28 0f 00 00 0a 28 4d 00 00 0a 13 04 11 04 08 28 4e 00 00 0a 00 02 28 4f 00 00 0a 00 11 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Lapsus_A_2147947205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Lapsus.A!MTB"
        threat_id = "2147947205"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lapsus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locked" ascii //weight: 1
        $x_1_2 = "AlertaRansom" ascii //weight: 1
        $x_1_3 = "ReadMe.txt" ascii //weight: 1
        $x_1_4 = ".onion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

