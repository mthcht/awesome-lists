rule TrojanDownloader_MSIL_Eves_A_2147697366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Eves.A"
        threat_id = "2147697366"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Eves"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b72bSILlzCwXBSrQ" ascii //weight: 1
        $x_1_2 = "QicowIGONydFEv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Eves_A_2147697366_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Eves.A"
        threat_id = "2147697366"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Eves"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Isass323.exe" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 39 00 38 00 2e 00 35 00 30 00 2e 00 31 00 35 00 39 00 2e 00 31 00 35 00 35 00 2f 00 [0-6] 2f 00 [0-5] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

