rule PWS_MSIL_Kelopol_A_2147643256_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Kelopol.A"
        threat_id = "2147643256"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kelopol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 6d 00 74 00 70 00 2e 00 [0-32] 59 00 6f 00 75 00 72 00 20 00 50 00 6f 00 6c 00 79 00 6d 00 6f 00 72 00 70 00 68 00 69 00 63 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 61 00 63 00 74 00 69 00 76 00 61 00 74 00 65 00 64 00 20 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 00 2d 00 2d 00 43 00 6f 00 64 00 65 00 64 00 20 00 62 00 79 00 20 00 43 00 6c 00 61 00 73 00 73 00 69 00 63 00 61 00 6c 00 2d 00 2d 00 5d 00 [0-16] 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = "You should be recieving logs shortly." wide //weight: 1
        $x_1_4 = "[Paste]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_MSIL_Kelopol_B_2147643594_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Kelopol.B"
        threat_id = "2147643594"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kelopol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 19 7e 0b 00 00 04 72 ?? ?? 00 70 28 ?? 00 00 0a 80 0b 00 00 04 38 03 00 02 1f}  //weight: 2, accuracy: Low
        $x_1_2 = "smtp.gmail.com" wide //weight: 1
        $x_1_3 = "Keylogger" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

