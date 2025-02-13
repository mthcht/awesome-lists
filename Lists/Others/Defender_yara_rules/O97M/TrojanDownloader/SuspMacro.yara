rule TrojanDownloader_O97M_SuspMacro_A_2147805676_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/SuspMacro.A"
        threat_id = "2147805676"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SuspMacro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Microsoft.XMLHTTP\")" ascii //weight: 1
        $x_1_2 = "write" ascii //weight: 1
        $x_1_3 = "savetofile" ascii //weight: 1
        $x_1_4 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_5 = ".Run(" ascii //weight: 1
        $x_1_6 = "cscript" ascii //weight: 1
        $x_1_7 = "move" ascii //weight: 1
        $x_1_8 = "Call" ascii //weight: 1
        $x_1_9 = ".Send" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

