rule TrojanDownloader_O97M_Otcontavir_2147711167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Otcontavir"
        threat_id = "2147711167"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Otcontavir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"ht\" & \"tp:\" & \"/\" & \"/\" & \"suc\" & \"esores.com.m\" & \"x/images/lo\" & \"go.g\" & \"if\"" ascii //weight: 1
        $x_1_2 = "http://sucesores.com.mx/images/logo.gif" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

