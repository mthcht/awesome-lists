rule PWS_MSIL_Steam_A_2147653709_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Steam.A"
        threat_id = "2147653709"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Steam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "***Steam Account***" wide //weight: 1
        $x_1_2 = "victim is:" wide //weight: 1
        $x_2_3 = {53 00 74 00 65 00 61 00 6d 00 20 00 49 00 6f 00 6e 00 6f 00 48 00 61 00 63 00 6b 00 65 00 72 00 20 00 76 00 [0-16] 42 00 79 00 20 00 49 00 6f 00 6e 00 6f 00 50 00 72 00 6f 00 78 00 79 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

