rule TrojanDropper_MSIL_Dyzoone_A_2147705711_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Dyzoone.A"
        threat_id = "2147705711"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dyzoone"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".EPROK.resources" ascii //weight: 1
        $x_1_2 = "ResourceWriter" ascii //weight: 1
        $x_1_3 = "System.Security.Cryptography.X509Certificates" ascii //weight: 1
        $x_1_4 = "EncoderFallback" ascii //weight: 1
        $x_2_5 = {55 70 6c 6f 61 64 73 57 65 6c 6c 63 6f 6e 6e 65 63 00}  //weight: 2, accuracy: High
        $x_2_6 = "Koqyright" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

