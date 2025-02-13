rule TrojanDownloader_O97M_Pogleggis_A_2147688751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Pogleggis.A"
        threat_id = "2147688751"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Pogleggis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= VBA.CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"ADODB.Stream\")" ascii //weight: 1
        $x_1_3 = ".Open \"GET\"," ascii //weight: 1
        $x_1_4 = "= Shell(Environ(\"TEMP\") & \"\\word.exe\"," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

