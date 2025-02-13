rule PWS_MSIL_Bahmajip_A_2147707071_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Bahmajip.A"
        threat_id = "2147707071"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bahmajip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 4b 02 00 00 6f}  //weight: 1, accuracy: High
        $x_1_2 = " / Pass: " wide //weight: 1
        $x_1_3 = "smtp.gmail.com" wide //weight: 1
        $x_1_4 = {4d 61 69 6c 41 64 64 72 65 73 73 00 73 65 74 5f 46 72 6f 6d 00 4d 61 69 6c 41 64 64 72 65 73 73 43 6f 6c 6c 65 63 74 69 6f 6e 00 67 65 74 5f 54 6f 00 73 65 74 5f 53 75 62 6a 65 63 74 00 67 65 74 5f 54 65 78 74 00 43 6f 6e 63 61 74 00 73 65 74 5f 42 6f 64 79 00 73 65 74 5f 50 6f 72 74 00 73 65 74 5f 45 6e 61 62 6c 65 53 73 6c}  //weight: 1, accuracy: High
        $x_1_5 = "Please put your email" wide //weight: 1
        $x_1_6 = "No Password found!" wide //weight: 1
        $x_1_7 = "Error!  Please enter a correct username and password" wide //weight: 1
        $x_1_8 = {4d 61 69 6c 41 64 64 72 65 73 73 43 6f 6c 6c 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

