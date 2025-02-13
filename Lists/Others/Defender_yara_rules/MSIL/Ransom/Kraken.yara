rule Ransom_MSIL_Kraken_A_2147729465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Kraken.A"
        threat_id = "2147729465"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kraken"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kraken.exe" wide //weight: 1
        $x_1_2 = "\"anti_forensic\":true," ascii //weight: 1
        $x_1_3 = "\"anti_revere\":true," ascii //weight: 1
        $x_1_4 = "When the researchers party hard, our parties harder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Kraken_2147729652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Kraken"
        threat_id = "2147729652"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kraken"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Dear %1!\\r\\nAll of your files such as documents, images, videos and other files\\r\\nwith the different names and extensions are encrypted." ascii //weight: 4
        $x_4_2 = "Read the instructions file named \\\"%2\\\" for more information." ascii //weight: 4
        $x_4_3 = "You can find this file everywhere on your computer." ascii //weight: 4
        $x_4_4 = "* Don't Delete Encrypted Files\\r\\n* Don't Modify Encrypted Files\\r\\n* Don't Rename Encrypted Files" ascii //weight: 4
        $x_6_5 = "\"name\": \"Kraken Cryptor\"" ascii //weight: 6
        $x_6_6 = "\"comment\": \"Researchers Editon: Zero Resistance\"" ascii //weight: 6
        $x_6_7 = "\"support_email\": \"nikolatesla@cock.li\"" ascii //weight: 6
        $x_6_8 = "\"support_email\": \"onionhelp@memeware.net\"" ascii //weight: 6
        $x_6_9 = "\"support_alternativea\": \"nikolateslaproton@protonmail.com\"" ascii //weight: 6
        $x_6_10 = "\"support_alternativea\": \"BM-2cWdhn4f5UyMvruDBGs5bK77NsCFALMJkR@bitmessage.ch\"" ascii //weight: 6
        $x_2_11 = "\"price_unit\": \"BTC\"" ascii //weight: 2
        $x_2_12 = "\"target_extensions\": [" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_6_*) and 3 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_6_*) and 4 of ($x_4_*))) or
            ((2 of ($x_6_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_6_*) and 2 of ($x_4_*))) or
            ((3 of ($x_6_*) and 1 of ($x_2_*))) or
            ((3 of ($x_6_*) and 1 of ($x_4_*))) or
            ((4 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Kraken_2147729652_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Kraken"
        threat_id = "2147729652"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kraken"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "126"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Kraken.exe" ascii //weight: 10
        $x_10_2 = "kraken Cryptor" ascii //weight: 10
        $x_10_3 = "KRAKEN ENCRYPT UNIQUE KEY" ascii //weight: 10
        $x_1_4 = "How can recovery my files?" ascii //weight: 1
        $x_1_5 = "We guarantee that you can recover all your files soon safely." ascii //weight: 1
        $x_1_6 = "You can decrypt one of your encrypted smaller file for free in the first contact with us." ascii //weight: 1
        $x_1_7 = "Are you want to decrypt all of your encrypted files? If yes! You need to pay for decryption service to us!" ascii //weight: 1
        $x_1_8 = "After your payment made, all of your encrypted files has been decrypted." ascii //weight: 1
        $x_1_9 = "How much is need to pay?" ascii //weight: 1
        $x_1_10 = "This price is for the contact with us in first week otherwise it will increase." ascii //weight: 1
        $x_1_11 = "DON'T MODIFY OR RENAME ENCRYPTED FILES!" ascii //weight: 1
        $x_1_12 = "DON'T USE THIRD PARTY, PUBLIC TOOLS/SOFTWARE TO DECRYPT YOUR FILES, THIS CAUSE DAMAGE YOUR FILES PERMANENTLY!" ascii //weight: 1
        $x_1_13 = "NO PAYMENT, NO DECRYPT" ascii //weight: 1
        $x_100_14 = "530de7d5-eb45-4ca3-afaa-255dc5c3489c" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 6 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_Kraken_B_2147730119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Kraken.B"
        threat_id = "2147730119"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kraken"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Kraken.exe" wide //weight: 1
        $x_1_2 = "\"anti_revere\":true," ascii //weight: 1
        $x_1_3 = "\"extension_bypass\":true," ascii //weight: 1
        $x_1_4 = "KRAKEN ENCRYPTED UNIQUE KEY" ascii //weight: 1
        $x_1_5 = {4e 6f 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 79 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 74 68 6f 75 74 [0-6] 4b 52 41 4b 45 4e 20 44 45 43 52 59 50 54 4f 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_Kraken_C_2147732026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Kraken.C"
        threat_id = "2147732026"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kraken"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kraken Cryptor" ascii //weight: 1
        $x_1_2 = "onionhelp@memeware.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Kraken_D_2147732027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Kraken.D"
        threat_id = "2147732027"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kraken"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Krypton\\source\\repos\\UAC\\UAC\\obj\\Release\\UAC.pdb" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Classes\\mscfile\\shell\\open\\command" wide //weight: 1
        $x_1_3 = "Kraken.exe" ascii //weight: 1
        $x_1_4 = "KRAKEN_UNIQUE_KEY" ascii //weight: 1
        $x_1_5 = "Kraken Cryptor" wide //weight: 1
        $x_1_6 = "vssadmin delete shadows /All" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

