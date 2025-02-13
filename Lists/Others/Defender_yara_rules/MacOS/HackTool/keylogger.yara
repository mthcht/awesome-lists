rule HackTool_MacOS_keylogger_D_2147903497_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/keylogger.D!MTB"
        threat_id = "2147903497"
        type = "HackTool"
        platform = "MacOS: "
        family = "keylogger"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/var/log/keystroke.log" ascii //weight: 1
        $x_1_2 = "ERROR: Unable to create event tap" ascii //weight: 1
        $x_1_3 = "Keylogging has begun" ascii //weight: 1
        $x_1_4 = "ERROR: Unable to open log file. Ensure that you have the proper permissions" ascii //weight: 1
        $x_1_5 = "CGEventTapCreate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

