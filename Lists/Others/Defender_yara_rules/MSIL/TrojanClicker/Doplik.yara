rule TrojanClicker_MSIL_Doplik_ADO_2147932463_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Doplik.ADO!MTB"
        threat_id = "2147932463"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Doplik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 17 6f ?? 00 00 0a 00 73 0b 00 00 0a 0b 07 72 01 00 00 70 6f ?? 00 00 0a 00 07 72 13 00 00 70 6f ?? 00 00 0a 00 06 07 73 0d 00 00 0a 80 01 00 00 04 7e 01 00 00 04 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

