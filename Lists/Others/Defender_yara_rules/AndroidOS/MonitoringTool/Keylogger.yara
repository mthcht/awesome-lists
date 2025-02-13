rule MonitoringTool_AndroidOS_Keylogger_A_334917_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Keylogger.A!MTB"
        threat_id = "334917"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Share Log File" ascii //weight: 1
        $x_1_2 = "monitor.mubeen.androidkeylogger" ascii //weight: 1
        $x_1_3 = "SendToServerTask" ascii //weight: 1
        $x_1_4 = "imageReader" ascii //weight: 1
        $x_1_5 = "isAccessibilitySettingsOn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Keylogger_B_339171_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Keylogger.B!MTB"
        threat_id = "339171"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "createConfirmDeviceCredentialIntent" ascii //weight: 1
        $x_1_2 = "com/pxdworks/typekeeper" ascii //weight: 1
        $x_1_3 = "KeyguardManager" ascii //weight: 1
        $x_1_4 = "TextTypingActivity" ascii //weight: 1
        $x_1_5 = "copyToClipboardInputEvent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_AndroidOS_Keylogger_C_349049_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Keylogger.C!MTB"
        threat_id = "349049"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tej.flashkeylogger" ascii //weight: 1
        $x_1_2 = "InputMonitorService" ascii //weight: 1
        $x_1_3 = "getKeys" ascii //weight: 1
        $x_1_4 = "OnKeyboardActionListener" ascii //weight: 1
        $x_1_5 = "getActiveNetworkInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_AndroidOS_Keylogger_D_361143_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Keylogger.D!MTB"
        threat_id = "361143"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyDetector" ascii //weight: 1
        $x_1_2 = "ContactsDictionary" ascii //weight: 1
        $x_1_3 = "key.txt" ascii //weight: 1
        $x_1_4 = "com/androapps/keystroke/logger" ascii //weight: 1
        $x_1_5 = "auto_dict.db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Keylogger_E_423434_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Keylogger.E!MTB"
        threat_id = "423434"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Keylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyLoggerAccessibilityService" ascii //weight: 1
        $x_1_2 = "com/gpow/androidkeylogger" ascii //weight: 1
        $x_1_3 = "KeyLogger.TermsAgreed" ascii //weight: 1
        $x_1_4 = "/keylogger_text_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

