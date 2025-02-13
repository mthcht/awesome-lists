rule TrojanDropper_O97M_TaskShed_YA_2147735479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/TaskShed.YA!MTB"
        threat_id = "2147735479"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "TaskShed"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateObject(\"Schedule.Service\")" ascii //weight: 1
        $x_1_2 = ".Create(ActionTypeExecutable)" ascii //weight: 1
        $x_1_3 = "= ActiveDocument." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

