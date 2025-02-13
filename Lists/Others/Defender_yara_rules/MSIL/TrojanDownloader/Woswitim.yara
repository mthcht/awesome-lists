rule TrojanDownloader_MSIL_Woswitim_A_2147712595_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Woswitim.A"
        threat_id = "2147712595"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Woswitim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "aHR0cDovL2F0ZW50b3NpbnRlcm5ldC5jb29tZXZhLmNvbS5jby9hdGVudG9zL2xvZ3Mvc3lzd293LmV4ZQ==" wide //weight: 2
        $x_1_2 = "c3lzd293LmV4ZQ==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

