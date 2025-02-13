rule Ransom_MSIL_DutCrypt_PI_2147751960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/DutCrypt.PI!MSR"
        threat_id = "2147751960"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DutCrypt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fucknorkey" wide //weight: 1
        $x_1_2 = "fucknohwid" wide //weight: 1
        $x_1_3 = "Rather have my files taken for ransom than my family" wide //weight: 1
        $x_1_4 = "Maak 200 euro in bitcoin over naar het bitcoin Adres of scan de qr code" ascii //weight: 1
        $x_1_5 = {5c 57 69 6e 64 6f 77 73 44 65 66 65 6e 64 65 72 5c 6f 62 6a 5c [0-16] 5c 41 70 70 6c 69 63 61 74 69 6f 6e 5f 44 65 66 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

