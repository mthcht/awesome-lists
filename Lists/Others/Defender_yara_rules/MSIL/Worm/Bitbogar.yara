rule Worm_MSIL_Bitbogar_A_2147685581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Bitbogar.A"
        threat_id = "2147685581"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bitbogar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BrotherConfig" ascii //weight: 1
        $x_1_2 = "EmailKeylogger" ascii //weight: 1
        $x_1_3 = "EmailYahooCam" ascii //weight: 1
        $x_1_4 = "SpreadToUsb" ascii //weight: 1
        $x_1_5 = "SpreadToStartup" ascii //weight: 1
        $x_1_6 = "SpreadToSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

