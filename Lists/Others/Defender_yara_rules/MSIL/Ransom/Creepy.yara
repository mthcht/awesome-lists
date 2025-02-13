rule Ransom_MSIL_Creepy_SK_2147753496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Creepy.SK!MTB"
        threat_id = "2147753496"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Creepy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Creepy Ransomware" ascii //weight: 5
        $x_1_2 = "get_crpkey" ascii //weight: 1
        $x_1_3 = "set_crpkey" ascii //weight: 1
        $x_1_4 = "Its a powerful ransomware" ascii //weight: 1
        $x_1_5 = "Ecnrypted your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

