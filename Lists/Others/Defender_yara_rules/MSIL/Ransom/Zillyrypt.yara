rule Ransom_MSIL_Zillyrypt_A_2147721776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Zillyrypt.A"
        threat_id = "2147721776"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zillyrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/ransom.php" wide //weight: 1
        $x_1_2 = "\\OkuBeni.txt" wide //weight: 1
        $x_1_3 = ".zilla" wide //weight: 1
        $x_1_4 = "Dosyalariniz Sifrelendi!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

