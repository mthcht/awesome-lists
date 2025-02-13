rule PWS_MSIL_Skonpri_A_2147679055_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Skonpri.A"
        threat_id = "2147679055"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Skonpri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "persiangig.com/filesForDownload.txt" wide //weight: 2
        $x_1_2 = "TurnOnWebCamAndTakePic" ascii //weight: 1
        $x_1_3 = "Temp_Keystroe_File_Name" ascii //weight: 1
        $x_1_4 = "33&664$#n0BodyCan't Find This :D" wide //weight: 1
        $x_1_5 = {4d 00 6f 00 72 00 65 00 45 00 76 00 69 00 6c 00 00 07 73 00 65 00 78 00 00 07 6b 00 69 00 72}  //weight: 1, accuracy: High
        $x_1_6 = "Y0U Can?!$FR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

