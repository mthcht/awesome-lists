rule TrojanDropper_O97M_Commprs_YA_2147731686_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Commprs.YA!MTB"
        threat_id = "2147731686"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Commprs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "In ActiveDocument.BuiltInDocumentProperties" ascii //weight: 1
        $x_1_2 = "Shell (" ascii //weight: 1
        $x_1_3 = ".FileSystemObject" ascii //weight: 1
        $x_1_4 = "As DocumentProperty" ascii //weight: 1
        $x_1_5 = ".Name = \"Comments\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

