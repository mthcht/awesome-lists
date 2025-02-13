rule Trojan_Win32_AutoitWorm_LJ_2147798831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AutoitWorm.LJ!MTB"
        threat_id = "2147798831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILECOPY ( @SCRIPTFULLPATH , @APPDATADIR & \"/Windows Photo Viewer.exe\" , $FC_OVERWRITE + $FC_CREATEPATH" ascii //weight: 1
        $x_1_2 = "FILECREATESHORTCUT ( @APPDATADIR & \"/Windows Photo Viewer.exe\" , @STARTUPDIR & \"\\Windows Photo Viewer.lnk" ascii //weight: 1
        $x_1_3 = "FILECOPY ( @APPDATADIR & \"/Windows Photo Viewer.exe\" , $USB [ $I ] & \"/IMG_3325.exe\" , $FC_OVERWRITE + $FC_CREATEPATH" ascii //weight: 1
        $x_1_4 = "http://adf.ly/q3397\" , \"http://adf.ly/q33Lk\" , \"http://adf.ly/q33Sg\" , \"http://adf.ly/q33VD\" , \"http://adf.ly/q33XI" ascii //weight: 1
        $x_1_5 = "skip_ad_button" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

