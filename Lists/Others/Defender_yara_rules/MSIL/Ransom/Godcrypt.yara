rule Ransom_MSIL_Godcrypt_2147729651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Godcrypt"
        threat_id = "2147729651"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Godcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Godsomware" ascii //weight: 1
        $x_1_2 = "Ooops, your files have been encrypted!" wide //weight: 1
        $x_1_3 = "Send $100 worth of bitcoin to this address:" wide //weight: 1
        $x_1_4 = "get_if_payment_method_bitcoin_" ascii //weight: 1
        $x_2_5 = "God Crypt v1.0" wide //weight: 2
        $x_2_6 = "Godsomware.My.Resources" ascii //weight: 2
        $x_2_7 = {47 6f 64 73 6f 6d 77 61 72 65 2e 46 6f 72 6d ?? 2e 72 65 73 6f 75 72 63 65 73}  //weight: 2, accuracy: Low
        $x_2_8 = "Godsomware.Resources.resources" ascii //weight: 2
        $x_2_9 = "Godsomware.exe" ascii //weight: 2
        $x_2_10 = "explorer.exe https://www.thestreet.com/investing/bitcoin/where-to-buy-bitcoin-14549594" wide //weight: 2
        $x_4_11 = "1M7jsxLEC3jsfWen1FP1N9uvTs19kkffj4" wide //weight: 4
        $x_4_12 = "Ransomware God Crypt v1.0 by NinjaGhost" ascii //weight: 4
        $x_4_13 = "get_WannaCry_ransom_note__Please_Read_Me__txt" ascii //weight: 4
        $x_4_14 = "WannaCry-ransom-note-@Please_Read_Me@-txt" wide //weight: 4
        $x_4_15 = "explorer.exe mailto:ninjacyber.com@gmail.com" wide //weight: 4
        $x_6_16 = {47 6f 64 73 6f 6d 77 61 72 65 20 62 79 20 4e 69 6e 6a 61 47 68 6f 73 74 5c 47 6f 64 73 6f 6d 77 61 72 65 5c 47 6f 64 73 6f 6d 77 61 72 65 [0-32] 47 6f 64 73 6f 6d 77 61 72 65 2e 70 64 62}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_4_*) and 6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_4_*) and 3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_4_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_4_*) and 5 of ($x_2_*))) or
            ((5 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_6_*) and 1 of ($x_4_*) and 6 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_4_*) and 6 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 5 of ($x_4_*))) or
            (all of ($x*))
        )
}

