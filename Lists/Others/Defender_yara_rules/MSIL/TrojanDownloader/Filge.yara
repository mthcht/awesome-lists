rule TrojanDownloader_MSIL_Filge_A_2147694394_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Filge.A"
        threat_id = "2147694394"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Filge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cDovL2dlLnR0L2FwaS8xL2ZpbGVzLz" wide //weight: 1
        $x_1_2 = "aHR0cDovL2RpcmVjdHhleC5uZXQvZT" wide //weight: 1
        $x_2_3 = "/c cd %temp% & start /B" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

