rule MonitoringTool_AndroidOS_SpyPhone_A_305594_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyPhone.A!MTB"
        threat_id = "305594"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyPhone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HideIcons" ascii //weight: 1
        $x_1_2 = "sivartech.com/spyphone/tutorial" ascii //weight: 1
        $x_1_3 = "HideMedia" ascii //weight: 1
        $x_1_4 = "SpyPhoneActivity" ascii //weight: 1
        $x_1_5 = "startVideoRecording" ascii //weight: 1
        $x_1_6 = "sivartech/spyphone/SpyPhoneApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_SpyPhone_B_313448_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyPhone.B!MTB"
        threat_id = "313448"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyPhone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sivartech/spyphone/SpyPhoneActivity" ascii //weight: 1
        $x_1_2 = "HideIcons" ascii //weight: 1
        $x_1_3 = "getSpyPhoneApp" ascii //weight: 1
        $x_1_4 = "onUserLeaveHint" ascii //weight: 1
        $x_1_5 = "_cHideMedia" ascii //weight: 1
        $x_1_6 = "SpyPhoneApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_SpyPhone_D_346021_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyPhone.D!MTB"
        threat_id = "346021"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyPhone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cHM6Ly9jb211bmljYXRpb25ub3cuY29tL3NjcmlwdHMvYXBwc19yZWdpc3Rlcl9hbmFseXNpcy5waHA=" ascii //weight: 1
        $x_1_2 = "aHR0cHM6Ly9jb211bmljYXRpb25ub3cuY29tL3NjcmlwdHMvYXBwc191cGRhdGVfYW5hbHlzaXMucGhw" ascii //weight: 1
        $x_1_3 = "startWhatsSpam" ascii //weight: 1
        $x_1_4 = "pilturent.com" ascii //weight: 1
        $x_1_5 = "enable_browser_ogads" ascii //weight: 1
        $x_1_6 = "ogads_javascript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule MonitoringTool_AndroidOS_SpyPhone_E_440042_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/SpyPhone.E!MTB"
        threat_id = "440042"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "SpyPhone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bGetSpyPhoneFull" ascii //weight: 1
        $x_1_2 = "/SpyPhone/" ascii //weight: 1
        $x_1_3 = "HideSavedMedia" ascii //weight: 1
        $x_1_4 = "spyphone_widget" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

