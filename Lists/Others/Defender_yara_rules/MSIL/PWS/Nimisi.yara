rule PWS_MSIL_Nimisi_A_2147691554_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Nimisi.A"
        threat_id = "2147691554"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nimisi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "password_value" wide //weight: 1
        $x_1_2 = {67 65 74 4d 53 4e 37 35 50 61 73 73 77 6f 72 64 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {74 00 36 00 4b 00 7a 00 58 00 68 00 43 00 68 00 [0-6] 44 00 79 00 6e 00 44 00 4e 00 53 00}  //weight: 1, accuracy: Low
        $x_1_4 = {26 00 75 00 72 00 6c 00 3d 00 00 0d 26 00 75 00 73 00 65 00 72 00 3d 00 00 0d 26 00 70 00 61 00 73 00 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

