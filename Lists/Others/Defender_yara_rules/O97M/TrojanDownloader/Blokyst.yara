rule TrojanDownloader_O97M_Blokyst_A_2147742637_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Blokyst.A"
        threat_id = "2147742637"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Blokyst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"\\Ap\" + \"pDa\" + \"ta\\Roa\" + \"ming\" & \"\\\"" ascii //weight: 1
        $x_1_2 = "'%APPDATA%\\fo' + 'ld1' + '\\pri' + 'nter.e' + 'xe')" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

