rule Ransom_MSIL_Gommyrypt_A_2147721782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Gommyrypt.A"
        threat_id = "2147721782"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gommyrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/btc.txt" wide //weight: 1
        $x_1_2 = "Fuck off." wide //weight: 1
        $x_1_3 = "TmFoLg==" wide //weight: 1
        $x_2_4 = "QUxMIE9GIFlPVVIgRklMRVMgSEFWRSBCRUVOIEVOQ1JZUFRFRCE=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Gommyrypt_AGO_2147850642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Gommyrypt.AGO!MTB"
        threat_id = "2147850642"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gommyrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 0d 2b 1d 08 72 ?? 08 00 70 07 09 91 8c 20 00 00 01 28 4b 00 00 0a 6f 4c 00 00 0a 26 09 17 58 0d 09 07 8e 69 32 dd}  //weight: 2, accuracy: Low
        $x_1_2 = "Admoooon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

