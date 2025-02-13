rule Ransom_MSIL_Elmyrypt_A_2147721783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Elmyrypt.A"
        threat_id = "2147721783"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Elmyrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Elmers Glue Locker" ascii //weight: 1
        $x_1_2 = "files have been covered in very sticky Elmer's Glue!" wide //weight: 1
        $x_2_3 = "1Drv9jAMsVZPeur18zbmtJTciAmaj5L9bo" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

