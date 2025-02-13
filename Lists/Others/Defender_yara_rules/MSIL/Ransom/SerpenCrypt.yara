rule Ransom_MSIL_SerpenCrypt_A_2147719885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SerpenCrypt.A!rsm"
        threat_id = "2147719885"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SerpenCrypt"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your documents, photos, videos, databases and other important files have been encrypted!" ascii //weight: 1
        $x_1_2 = "The files have been encrypted using AES256 and RSA2048 encryption (unbreakable)" ascii //weight: 1
        $x_1_3 = "To decrypt your files you need to buy the special software 'Serpent Decrypter'." ascii //weight: 1
        $x_1_4 = "<a href=\"[paymentdomain0]/[hwid]\" target=\"_BLANK\">[paymentdomain0]/[hwid]</a>" ascii //weight: 1
        $x_1_5 = "<a href=\"[paymentdomain1]/[hwid]\" target=\"_BLANK\">[paymentdomain1]/[hwid]</a>" ascii //weight: 1
        $x_1_6 = "Follow the instructions to buy 'Serpent Decrypter'" ascii //weight: 1
        $x_1_7 = {5b 70 61 79 6d 65 6e 74 64 6f 6d 61 69 6e 30 5d 2f 5b 68 77 69 64 5d 0d 0a 5b 70 61 79 6d 65 6e 74 64 6f 6d 61 69 6e 31 5d 2f 5b 68 77 69 64 5d}  //weight: 1, accuracy: High
        $x_1_8 = "== PLEASE READ THIS MESSAGE CAREFULLY ==" ascii //weight: 1
        $x_1_9 = "3o4kqe6khkfgx25g.onion" ascii //weight: 1
        $x_1_10 = "//vdpbkmwbnp.pw" ascii //weight: 1
        $x_1_11 = "//hnxrvobhgm.pw" ascii //weight: 1
        $x_1_12 = "//146.71.84.110:8080" ascii //weight: 1
        $x_1_13 = "//185.175.208.12:8080" ascii //weight: 1
        $x_1_14 = "//94.140.120.88:8080" ascii //weight: 1
        $x_1_15 = ".serpent" ascii //weight: 1
        $x_1_16 = "agntsvc.exeisqlplussvc.exe" ascii //weight: 1
        $x_1_17 = "how_to_decrypt_your_files" ascii //weight: 1
        $x_1_18 = "serpent.ini" ascii //weight: 1
        $x_1_19 = "[hwid]" ascii //weight: 1
        $x_1_20 = "[paymentdomain" ascii //weight: 1
        $x_1_21 = "\\HOW_TO_DECRYPT_YOUR_FILES_" ascii //weight: 1
        $x_1_22 = "encryptionsoftware.Resources" ascii //weight: 1
        $x_1_23 = "<rsa_public></rsa_public>" ascii //weight: 1
        $x_1_24 = "_PWSALT_" ascii //weight: 1
        $x_1_25 = {00 4d 55 54 45 58 30 30 30 30 30 31 00}  //weight: 1, accuracy: High
        $x_1_26 = {00 5c 24 72 65 63 79 63 6c 65 2e 62 69 6e 5c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_SerpenCrypt_B_2147721051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/SerpenCrypt.B"
        threat_id = "2147721051"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SerpenCrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "contains SFX script commands" wide //weight: 1
        $x_1_2 = "TempMode" wide //weight: 1
        $x_1_3 = "Silent=1" wide //weight: 1
        $x_1_4 = "Overwrite=2" wide //weight: 1
        $x_1_5 = "Setup=Txoeoaon.exe" wide //weight: 1
        $x_1_6 = "Hhrrxoeoaon.bin" wide //weight: 1
        $x_1_7 = "Microsoft.VisualBasic.ApplicationServices" ascii //weight: 1
        $x_1_8 = "System.Reflection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

