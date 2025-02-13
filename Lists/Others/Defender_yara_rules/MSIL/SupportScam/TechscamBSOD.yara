rule SupportScam_MSIL_TechscamBSOD_A_2147717717_0
{
    meta:
        author = "defender2yara"
        detection_name = "SupportScam:MSIL/TechscamBSOD.A"
        threat_id = "2147717717"
        type = "SupportScam"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TechscamBSOD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 53 79 73 74 65 6d 5f 4f 70 74 69 6d 69 7a 65 72 5c 53 59 53 42 6c 75 65 53 63 72 65 65 6e 77 69 6e 37 5c 53 42 53 43 50 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 53 42 53 43 50 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = "Confirm to restart the computer" wide //weight: 1
        $x_1_3 = "\\VinCE" wide //weight: 1
        $x_1_4 = "Still the error occurs and windows was not able to fix it. Call Windows support for possible fixes" wide //weight: 1
        $x_1_5 = "payment@vithobaa.com" wide //weight: 1
        $x_1_6 = "Vithobaa#1191" wide //weight: 1
        $x_1_7 = {53 42 53 43 50 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_8 = {24 66 35 64 30 61 36 62 66 2d 32 31 63 30 2d 34 38 64 63 2d 39 31 30 63 2d 65 39 31 31 62 66 34 36 34 36 62 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

