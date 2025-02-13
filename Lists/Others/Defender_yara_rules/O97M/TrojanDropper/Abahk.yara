rule TrojanDropper_O97M_Abahk_YA_2147735307_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Abahk.YA!MTB"
        threat_id = "2147735307"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Abahk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\AutoHotkeyU32.exe" ascii //weight: 1
        $x_1_2 = "Call Shell(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

