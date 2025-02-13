rule TrojanDownloader_O97M_Tnega_AR_2147754567_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Tnega.AR!MTB"
        threat_id = "2147754567"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_2 = "DownloadFile" ascii //weight: 1
        $x_5_3 = {2f 2f 73 6d 61 72 74 73 63 72 65 65 6e 74 65 73 74 72 61 74 69 6e 67 73 32 2e 6e 65 74 2f [0-31] 2e 65 78 65 4f 00 68 74 74 70 73 3a}  //weight: 5, accuracy: Low
        $x_1_4 = ".Run CreateObject(\"Scripting.FileSystemObject\")." ascii //weight: 1
        $x_1_5 = {2e 65 78 65 22 4f 00 68 74 74 70 73 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Tnega_SS_2147754625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Tnega.SS!MTB"
        threat_id = "2147754625"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Scripting.FileSystemObject\").FileExists(szFile)" ascii //weight: 1
        $x_1_2 = "Set oNode = oXML.CreateElement(\"base64\")" ascii //weight: 1
        $x_1_3 = "= Environ(\"UserProfile\") & \"\\AppData\\Local\\Microsoft\\Notice" ascii //weight: 1
        $x_1_4 = "dllPath = workDir & \"\\\" & binName" ascii //weight: 1
        $x_1_5 = "binName = \"wsdts.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Tnega_PRB_2147754722_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Tnega.PRB!MTB"
        threat_id = "2147754722"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "= ActiveDocument.Path & \"\\\" & ActiveDocument.Name" ascii //weight: 1
        $x_1_2 = "= curDocName & \" .docx\"" ascii //weight: 1
        $x_1_3 = "workDir = Environ(\"UserProfile\") & \"\\AppData\\Local\\Microsoft\\OneNote\"" ascii //weight: 1
        $x_1_4 = "dllPath = workDir & \"\\onenote.db\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Tnega_SA_2147755710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Tnega.SA!MTB"
        threat_id = "2147755710"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Dm = \"http://craghoppers.icu/Order.jpg|||msxml2.xmlhttp" ascii //weight: 2
        $x_2_2 = "Dm = \"http://moveis-schuster-com.ga/Order.jpg|||msxml2.xmlhttp" ascii //weight: 2
        $x_1_3 = "Set xmlHttp = CreateObject(VB)" ascii //weight: 1
        $x_1_4 = "g = Split(Dm, \"|||\")" ascii //weight: 1
        $x_1_5 = ".Open \"get\", strURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_O97M_Tnega_RA_2147756806_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Tnega.RA!MTB"
        threat_id = "2147756806"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "+ \"objShell.Run Base64Decode(\"" ascii //weight: 1
        $x_1_2 = "= \"C:\\Windows\\System32\\w\" + \"script\" + \".exe \"" ascii //weight: 1
        $x_1_3 = "\"WScript.\" + \"She\" + \"ll\"" ascii //weight: 1
        $x_1_4 = {2b 20 22 2e 22 20 2b 20 22 76 22 0d 0a [0-5] 20 3d 20 00 20 2b 20 22 62 73 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Tnega_RA_2147756806_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Tnega.RA!MTB"
        threat_id = "2147756806"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GetDllName = \"C:\\ProgramData\\desktop.dat\"" ascii //weight: 1
        $x_1_2 = ".CreateElement(\"base64\")" ascii //weight: 1
        $x_1_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 0d 0a 20 20 20 20 [0-15] 20 3d 20 4c 65 66 74 28 [0-15] 2c 20 49 6e 53 74 72 52 65 76 28 [0-15] 2c 20 22 2e 22 29 20 2d 20 31 29}  //weight: 1, accuracy: Low
        $x_1_4 = "CreateObject(\"Word.Application\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

