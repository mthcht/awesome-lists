rule Ransom_MSIL_Nojocrypt_A_2147709088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Nojocrypt.A"
        threat_id = "2147709088"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nojocrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "humains sans emplois, en cherche pas les" ascii //weight: 1
        $x_1_2 = "Moyen de Payement:" ascii //weight: 1
        $x_1_3 = "Veuillez envoyer les codes des cartes" ascii //weight: 1
        $x_1_4 = "FileLocker." ascii //weight: 1
        $x_1_5 = "fr-fr/acheter/trouver-des-points-de-vente/" ascii //weight: 1
        $x_1_6 = "blocage sans Payer sera automatiquement rejet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

