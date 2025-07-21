rule Ransom_MSIL_Bert_A_2147947001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Bert.A"
        threat_id = "2147947001"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hello from Bert!" wide //weight: 1
        $x_1_2 = "encryptedbybert" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

