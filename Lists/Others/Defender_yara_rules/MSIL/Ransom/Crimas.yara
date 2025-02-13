rule Ransom_MSIL_Crimas_A_2147689177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crimas.A"
        threat_id = "2147689177"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crimas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoMaster" ascii //weight: 1
        $x_1_2 = "HOW TO DECRYPT FILES.txt" wide //weight: 1
        $x_1_3 = "/ps.ce" wide //weight: 1
        $x_1_4 = "/tx.ce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

