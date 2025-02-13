rule TrojanDownloader_O97M_Kodviron_A_2147689826_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Kodviron.A"
        threat_id = "2147689826"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kodviron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sub Auto_Open()" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"MSXML2.XMLHTTP\")" ascii //weight: 1
        $x_1_3 = "ChrW(104) & ChrW(116) & ChrW(116) & ChrW(112) & ChrW(58) & ChrW(47) & ChrW(47) &" ascii //weight: 1
        $x_1_4 = "), Environ(ChrW(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Kodviron_B_2147690199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Kodviron.B"
        threat_id = "2147690199"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Kodviron"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_2 = "= CreateObject(\"msxml2.xmlhttp\")" ascii //weight: 1
        $x_1_3 = "Environ(hextostring(Chr$(53) & Chr$(52) & Chr$(52) & Chr$(53) & Chr$(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

