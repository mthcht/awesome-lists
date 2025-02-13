rule Ransom_MSIL_RubbrCrypt_PA_2147830939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RubbrCrypt.PA!MTB"
        threat_id = "2147830939"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RubbrCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Rubber_Decrypt0r.txt" wide //weight: 1
        $x_1_2 = "Your data is encrypted with a special encryption software" wide //weight: 1
        $x_1_3 = ".CRYPT" wide //weight: 1
        $x_1_4 = "RubberDucky_Crypt0r" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

