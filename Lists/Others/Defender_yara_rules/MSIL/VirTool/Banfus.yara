rule VirTool_MSIL_Banfus_A_2147697365_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Banfus.A"
        threat_id = "2147697365"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banfus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1d 00 00 11 00 02 28 ?? 00 00 0a 00 02 02 8e b7 17 da 91 0d 28 ?? 00 00 0a 03 6f ?? 00 00 0a 13 04 02 8e b7 17 d6 8d 59 00 00 01 0c 16 0a 16 02}  //weight: 1, accuracy: Low
        $x_1_2 = "cdpapxalZZZsssAAAvbccdpapxalZZZss" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

