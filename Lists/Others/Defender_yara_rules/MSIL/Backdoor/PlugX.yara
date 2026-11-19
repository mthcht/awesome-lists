rule Backdoor_MSIL_PlugX_GK_2147982437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/PlugX.GK!MTB"
        threat_id = "2147982437"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PlugX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kill Processes" ascii //weight: 1
        $x_1_2 = "Get Passwords" ascii //weight: 1
        $x_1_3 = "Get KeyStrokes" ascii //weight: 1
        $x_1_4 = "http://backdoor" wide //weight: 1
        $x_1_5 = "\\CurrentWallpaper.Bmp" ascii //weight: 1
        $x_1_6 = "Keylogger_Enable" ascii //weight: 1
        $x_1_7 = "Keylogger" ascii //weight: 1
        $x_1_8 = "SELECT * FROM moz_logins" ascii //weight: 1
        $x_1_9 = "Get Process DLLs" ascii //weight: 1
        $x_1_10 = "Get Clipboard" ascii //weight: 1
        $x_1_11 = "Suspend Processes" ascii //weight: 1
        $x_1_12 = "RemoteControl Screen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

