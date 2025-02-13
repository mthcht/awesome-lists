rule TrojanDownloader_O97M_Daoyap_B_2147696457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Daoyap.B"
        threat_id = "2147696457"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Daoyap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set cuperMan = CreateObject(\"Adodb\" + ribak + \".Stream\")" ascii //weight: 1
        $x_1_2 = "tempFolder = processEnv(\"TE\" + \"M\" & \"P\")" ascii //weight: 1
        $x_1_3 = "sublocaBADOX.Open \"G\" + \"ET\", Redistribute(handle, " ascii //weight: 1
        $x_1_4 = "cuperMan.savetofile tabindexLOG, 2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Daoyap_B_2147696457_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Daoyap.B"
        threat_id = "2147696457"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Daoyap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set WinHttpReq = CreateObject(Microsoft.XMLHTTP) WinHttpReq.Open" ascii //weight: 1
        $x_1_2 = "WinHttpReq = CreateObject(\"Microsoft.XMLHTTP\"): WinHttpReq.Open \"GET\", myURL, False" ascii //weight: 1
        $x_1_3 = "oStream = CreateObject(\"ADODB.Stream\")" ascii //weight: 1
        $x_1_4 = "oStream.SaveToFile (\"C:\\Systems\\windows.exe\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Daoyap_C_2147706816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Daoyap.C"
        threat_id = "2147706816"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Daoyap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " + \".\" + \"e\" + \"x\" + \"e" ascii //weight: 1
        $x_1_2 = {68 74 74 70 52 65 71 75 65 73 74 2e 4f 70 65 6e 20 22 47 22 20 2b 20 [0-8] 20 2b 20 22 45 54 22}  //weight: 1, accuracy: Low
        $x_1_3 = "tempFolder = processEnv(\"TEM\" + \"P\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Daoyap_C_2147706816_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Daoyap.C"
        threat_id = "2147706816"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Daoyap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "102"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Zar = Array(412, 424" ascii //weight: 1
        $x_1_2 = "Open \"GET\", Redistribute(Zar, 44)" ascii //weight: 1
        $x_100_3 = "tempFile = tempFolder + \"\\etsbabk.exe" ascii //weight: 100
        $x_1_4 = "Zar = Array(433, 445, 445, 441" ascii //weight: 1
        $x_1_5 = ".Open \"GET\", Redistribute(Zar, 47), False" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Daoyap_C_2147706816_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Daoyap.C"
        threat_id = "2147706816"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Daoyap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "= \"h\" & Chr(116) & Chr(116) & Chr(112) & Chr(58) & \"/\" & Chr(47) & C" ascii //weight: 1
        $x_1_2 = "= \"h\" & \"t\" & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) &" ascii //weight: 1
        $x_1_3 = "& \".\" & Chr(101) & Chr(120) & Chr(101)" ascii //weight: 1
        $x_1_4 = "Chr(46) & \"e\" & \"x\" & Chr(101)" ascii //weight: 1
        $x_1_5 = "(\"T\" + Chr(69) + \"MP\")" ascii //weight: 1
        $x_1_6 = {2b 20 43 68 72 28 36 38 29 20 2b 20 22 [0-96] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_O97M_Daoyap_D_2147707224_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Daoyap.D"
        threat_id = "2147707224"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Daoyap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Microsoft\" + \".XMLHTTP\")" ascii //weight: 1
        $x_1_2 = "Adodb\" + \".Stream\")" ascii //weight: 1
        $x_1_3 = "Shell\" + \".Application\")" ascii //weight: 1
        $x_1_4 = "WScript\" + \".Shell\")" ascii //weight: 1
        $x_1_5 = {52 65 70 6c 61 63 65 28 22 22 20 2b 20 22 54 22 20 2b 20 22 45 ?? ?? 4d 22 20 2b 20 22 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_O97M_Daoyap_E_2147708701_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Daoyap.E"
        threat_id = "2147708701"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Daoyap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rosoft\", 6) + Left(\".XMLHTTP" ascii //weight: 1
        $x_1_2 = "= CreateObject(\"Adodb.Stream\")" ascii //weight: 1
        $x_1_3 = "= CreateObject(\"Shell.Application\")" ascii //weight: 1
        $x_1_4 = "Shell \"cmd /c RD /S /Q \" &" ascii //weight: 1
        $x_1_5 = {2b 20 52 65 70 6c 61 63 65 28 22 5c [0-15] 2e 74 78 74 22 2c 20 22 74 22 2c 20 22 65 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

