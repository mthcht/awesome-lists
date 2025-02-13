rule Trojan_MSIL_Ploprolo_A_2147707521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ploprolo.A"
        threat_id = "2147707521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ploprolo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "U2V0VGhyZWFkQ29udGV4dA==" ascii //weight: 1
        $x_1_2 = "V3JpdGVQcm9jZXNzTWVtb3J5" ascii //weight: 1
        $x_1_3 = "Rm9sZGVyTmFtZVxuLmV4ZQ==" ascii //weight: 1
        $x_1_4 = "VXBsb2FkUmVwb3J0TG9naW4uYXNteA==" ascii //weight: 1
        $x_1_5 = "QXZhc3RTdmM=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

