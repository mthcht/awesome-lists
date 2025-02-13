rule Ransom_MSIL_Loki_DA_2147771354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Loki.DA!MTB"
        threat_id = "2147771354"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All your files are encrypted" ascii //weight: 1
        $x_1_2 = "HowToDecrypt.txt" ascii //weight: 1
        $x_1_3 = "Credit_Cards.log" ascii //weight: 1
        $x_1_4 = ".loki" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Loki_DB_2147792968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Loki.DB!MTB"
        threat_id = "2147792968"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Loki locker" ascii //weight: 1
        $x_1_2 = "loki___Copy" ascii //weight: 1
        $x_1_3 = "Do not rename encrypted files" ascii //weight: 1
        $x_1_4 = "How to obtain Bitcoins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Loki_MBIS_2147890350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Loki.MBIS!MTB"
        threat_id = "2147890350"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Loki"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 18 11 19 11 1a 28 ?? 00 00 06 13 1b 07 11 16 11 1b 20 00 01 00 00 5d d2 9c 00 11 15 17 59 13 15 11 15 16 fe 04 16 fe 01 13 1c 11 1c 2d a9}  //weight: 1, accuracy: Low
        $x_1_2 = "8845USB4Z554IHYF74YIDA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

