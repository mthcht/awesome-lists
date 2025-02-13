rule Ransom_MSIL_Tarocrypt_A_2147708526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Tarocrypt.A"
        threat_id = "2147708526"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tarocrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 00 11 5e 00 5b 00 30 00 2d 00 39 00 5d 00 2b 00 24 00 01 13 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 00 25 7b 00 30 00 7d 00 20 00 7b 00 31 00 7d 00 20 00 48 00 54 00 54 00 50 00 2f 00 31 00 2e 00 31 00}  //weight: 1, accuracy: High
        $x_2_2 = "%APPDATA%\\OdnUqnxVqtAcmfpq4n\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Tarocrypt_A_2147708526_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Tarocrypt.A"
        threat_id = "2147708526"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tarocrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 6f 00 6e 00 65 00 4c 00 6f 00 63 00 6b 00 00 13 46 00 69 00 6e 00 64 00 46 00 49 00 4c 00 45 00 53}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 44 00 6f 00 6e 00 65 00 4c 00 6f 00 63 00 6b 00 00 7b 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 5c 00 5b 00 5e 00 5c 00 5c 00 5d 00 2b 00 5c 00 5c 00 28 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 24 00 7c 00 [0-128] 24 00 7c 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 24 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {13 44 00 6f 00 6e 00 65 00 4c 00 6f 00 63 00 6b 00 3d 00 00 07 2a 00 2e 00 2a 00 00 17 5e 00 28 00 5b 00 41 00 2d 00 5a 00 5d 00 3a 00 5c 00 5c 00 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_Tarocrypt_B_2147708562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Tarocrypt.B"
        threat_id = "2147708562"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tarocrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 00 33 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 2f 00 61 00 6c 00 6c 00 2f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {67 00 65 00 74 00 3d 00 00 03 3a 00 00 03 26 00 00 09 73 00 65 00 74 00 3d 00 00 13 72 00 65 00 63 00 65 00 69 00 76 00 65 00 64 00 3d 00 00 09 6e 00 75 00 6c 00 6c 00 00 13 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

