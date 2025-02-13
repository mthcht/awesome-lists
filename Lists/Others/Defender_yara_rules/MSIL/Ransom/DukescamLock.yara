rule Ransom_MSIL_DukescamLock_A_2147716862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/DukescamLock.A"
        threat_id = "2147716862"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DukescamLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 49 00 4c 00 45 00 4e 00 54 00 20 00 45 00 58 00 45 00 53 00 5c 00 4a 00 55 00 4e 00 4b 00 43 00 4c 00 45 00 41 00 4e 00 45 00 52 00 5c 00 4a 00 75 00 6e 00 6b 00 5f 00 62 00 6c 00 61 00 63 00 6b 00 73 00 63 00 72 00 65 00 65 00 6e 00 5c 00 46 00 72 00 65 00 65 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 6d 00 61 00 6e 00 61 00 67 00 65 00 72 00 5c 00 6f 00 62 00 6a 00 5c 00 78 00 38 00 36 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 46 00 72 00 65 00 65 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 2e 00 70 00 64 00 62 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {59 00 6f 00 75 00 72 00 20 00 6b 00 65 00 79 00 20 00 73 00 65 00 65 00 6d 00 73 00 20 00 74 00 6f 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 78 00 70 00 69 00 72 00 65 00 64 00 2c 00 20 00 50 00 6c 00 65 00 61 00 73 00 65 00 20 00 63 00 61 00 6c 00 6c 00 20 00 61 00 74 00 20 00 [0-32] 20 00 74 00 6f 00 20 00 67 00 65 00 74 00 20 00 61 00 20 00 6e 00 65 00 77 00 20 00 6f 00 6e 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Microsoft Windows Activation" wide //weight: 1
        $x_1_4 = "Closing of the registration form is not allowed" wide //weight: 1
        $x_2_5 = "teamviewer_by_bitingduke" ascii //weight: 2
        $x_1_6 = "Your Windows Licence has Expired , Please get a new one by calling on +1-888" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

