rule Ransom_MSIL_Extazy_AMTB_2147966851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Extazy!AMTB"
        threat_id = "2147966851"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Extazy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/r /f /t 5 /c \"ROLEX EXTAZY: Your PC is now destroyed.\"" ascii //weight: 1
        $x_2_2 = "ROLEX_EXTAZY_KEY_256_BIT_!!" ascii //weight: 2
        $x_2_3 = ".rolex" ascii //weight: 2
        $x_1_4 = "EXTAZY_ProcessedByFody" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

