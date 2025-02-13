rule Ransom_MSIL_Lockerrip_A_2147717589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Lockerrip.A"
        threat_id = "2147717589"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lockerrip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 69 6c 6c 65 72 4c 6f 63 6b 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "encrypt .rip" ascii //weight: 1
        $x_1_3 = "sua chave serao eliminadas em 48 horas." ascii //weight: 1
        $x_1_4 = {5c 4b 69 6c 6c 65 72 4c 6f 63 6b 65 72 5c 4b 69 6c 6c 65 72 4c 6f 63 6b 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4b 69 6c 6c 65 72 4c 6f 63 6b 65 72 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_5 = {24 38 33 39 65 39 33 38 65 2d 64 31 34 38 2d 34 31 35 39 2d 39 39 36 33 2d 31 36 35 33 30 35 63 64 65 65 36 31 00}  //weight: 1, accuracy: High
        $x_1_6 = "bntDecrypter" ascii //weight: 1
        $x_1_7 = "criptografia AES 256 BIT Muito forte.Realize o pagamento em:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

