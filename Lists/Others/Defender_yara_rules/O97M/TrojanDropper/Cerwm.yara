rule TrojanDropper_O97M_Cerwm_A_2147730709_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Cerwm.A!MTB"
        threat_id = "2147730709"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Cerwm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell (\"cmd /c certutil.exe -decodehex %temp%\\" ascii //weight: 1
        $x_1_2 = "wmic path win32_process call create %temp%\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

