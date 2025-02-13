rule Ransom_MSIL_WannaMadCrypt_PA_2147784836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaMadCrypt.PA!MTB"
        threat_id = "2147784836"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaMadCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "RansomwareWannaMad" wide //weight: 2
        $x_1_2 = ".hacked" wide //weight: 1
        $x_1_3 = ".WannaMad" wide //weight: 1
        $x_2_4 = "Oops.. You Has Been Encrypted." wide //weight: 2
        $x_2_5 = {5c 57 61 6e 6e 61 4d 61 64 5c [0-16] 5c [0-16] 44 65 62 75 67 5c 57 61 6e 6e 61 4d 61 64 2e 70 64 62}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_WannaMadCrypt_PB_2147788116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/WannaMadCrypt.PB!MTB"
        threat_id = "2147788116"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WannaMadCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README.txt" wide //weight: 1
        $x_1_2 = "You were encrypted by WannaMad" wide //weight: 1
        $x_1_3 = "has been encrypted" wide //weight: 1
        $x_1_4 = "C:\\Program Files\\System32\\WannaMad" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

