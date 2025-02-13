rule PWS_MSIL_Cidekoq_A_2147722643_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Cidekoq.A"
        threat_id = "2147722643"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cidekoq"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Ovidiy.exe" ascii //weight: 3
        $x_2_2 = "HttpWebRequest" ascii //weight: 2
        $x_2_3 = "System.net" ascii //weight: 2
        $x_1_4 = "HENKFAPNMGHLEFJGHHLDPJDHEDHHCBKBJJPA" ascii //weight: 1
        $x_1_5 = "Ovidiy.g.resources" ascii //weight: 1
        $x_1_6 = "ConfuserEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

