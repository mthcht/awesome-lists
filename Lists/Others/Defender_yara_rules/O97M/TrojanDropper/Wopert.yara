rule TrojanDropper_O97M_Wopert_2147712325_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Wopert"
        threat_id = "2147712325"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Wopert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VlZaV05GUldXbGRVYTFwV1lrVTFVbFpYY3pWU01VNVdaVVZaUFE9PQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

