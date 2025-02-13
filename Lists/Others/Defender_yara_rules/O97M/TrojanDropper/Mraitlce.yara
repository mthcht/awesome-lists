rule TrojanDropper_O97M_Mraitlce_E_2147778199_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Mraitlce.E!MTB"
        threat_id = "2147778199"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Mraitlce"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 [0-16] 2c 20 32 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateObject(\"WScript.Shell\")" ascii //weight: 1
        $x_1_3 = ".exe\"" ascii //weight: 1
        $x_1_4 = "WriteBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

