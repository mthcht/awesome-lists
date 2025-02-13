rule TrojanSpy_MSIL_Kostioul_A_2147718120_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Kostioul.A"
        threat_id = "2147718120"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kostioul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 00 4d 00 [0-10] 43 00 4f 00 4e 00 46 00 49 00 47 [0-10] 55 00 4e 00 50 00 45 00 [0-16] 55 00 52 00 41 00 4c 00 59 00 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

