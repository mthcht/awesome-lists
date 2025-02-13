rule Ransom_MSIL_Janelle_PAA_2147793597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Janelle.PAA!MTB"
        threat_id = "2147793597"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Janelle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "important files are encrypted" wide //weight: 1
        $x_1_2 = "EncryptedKey.txt" wide //weight: 1
        $x_1_3 = ".JANELLE" wide //weight: 1
        $x_1_4 = "virus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

