rule TrojanDownloader_O97M_Motczs_YB_2147743750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Motczs.YB!MSR"
        threat_id = "2147743750"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Motczs"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attribute VB_Base = \"1Normal.ThisDocument\"" ascii //weight: 1
        $x_1_2 = "Motobit Software, http://Motobit.cz" ascii //weight: 1
        $x_1_3 = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")" ascii //weight: 1
        $x_1_4 = "appDataLocation = \"C:\\programdata\\Micorsoft\\\"" ascii //weight: 1
        $x_1_5 = "quick_launch_location = appDataLocation & \"Microsoft.vbs\"" ascii //weight: 1
        $x_1_6 = "CreateObject(\"WScript.Shell\").Run quick_launch_location" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

