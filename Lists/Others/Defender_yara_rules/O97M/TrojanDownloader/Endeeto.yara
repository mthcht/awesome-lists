rule TrojanDownloader_O97M_Endeeto_A_2147688622_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Endeeto.A"
        threat_id = "2147688622"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Endeeto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"MSXML2.XMLHTTP\")" ascii //weight: 1
        $x_1_2 = ".Open \"GET\"," ascii //weight: 1
        $x_1_3 = ".Send \"123dt\"" ascii //weight: 1
        $x_1_4 = {2e 72 65 61 64 79 53 74 61 74 65 20 3c 3e 20 34 0d 0a 20 20 20 20 44 6f 45 76 65 6e 74 73 0d 0a 20 20 20 20 4c 6f 6f 70}  //weight: 1, accuracy: High
        $x_1_5 = "Glreg = Environ(\"WINDIR\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Endeeto_B_2147688748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Endeeto.B"
        threat_id = "2147688748"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Endeeto"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= CreateObject(\"MSXML2.XMLHTTP\")" ascii //weight: 1
        $x_1_2 = ".Open \"GET\"," ascii //weight: 1
        $x_1_3 = {50 75 62 6c 69 63 20 53 75 62 20 57 50 41 4d 48 4f 28 29 0d 0a 20 20 20 20 44 6f 77 6e 6c 6f 61 64 5f 46 69 6c 65}  //weight: 1, accuracy: High
        $x_1_4 = {2e 72 65 61 64 79 53 74 61 74 65 20 3c 3e 20 34 0d 0a 20 20 20 20 44 6f 45 76 65 6e 74 73 0d 0a 20 20 20 20 4c 6f 6f 70}  //weight: 1, accuracy: High
        $x_1_5 = "Environ(\"HOMEPATH\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

