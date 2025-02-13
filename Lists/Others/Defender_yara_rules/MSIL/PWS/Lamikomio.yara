rule PWS_MSIL_Lamikomio_A_2147705935_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Lamikomio.A"
        threat_id = "2147705935"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lamikomio"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ", Level Garena :" wide //weight: 1
        $x_1_2 = "Thank You For Use! #" wide //weight: 1
        $x_6_3 = "santiagomunezfifa@gmail.com" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

