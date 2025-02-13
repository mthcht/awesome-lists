rule TrojanSpy_AndroidOS_Hermit_A_2147822415_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Hermit.A"
        threat_id = "2147822415"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Hermit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ROOT_INFO_SUCCEDED" ascii //weight: 1
        $x_1_2 = "RUNNING_APP_PROCESS" ascii //weight: 1
        $x_1_3 = "vpsseed" ascii //weight: 1
        $x_1_4 = "LOCATION_INFO_CHANGED" ascii //weight: 1
        $x_1_5 = "PLATFORM_LEVELS_CHANGES" ascii //weight: 1
        $x_1_6 = "setCellularUpload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Hermit_B_2147824904_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Hermit.B"
        threat_id = "2147824904"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Hermit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "voida2dfae4581f5" ascii //weight: 1
        $x_1_2 = "SCREEN_ON_REQUESTED" ascii //weight: 1
        $x_1_3 = "watchdogUninstallTs" ascii //weight: 1
        $x_1_4 = "EXPLOIT_SUCCEDED" ascii //weight: 1
        $x_1_5 = "PLATFORM_LIMIT_REACHED" ascii //weight: 1
        $x_1_6 = "PERMISSION_INFO_DENIED" ascii //weight: 1
        $x_1_7 = "RECORDER_EVENT_ERROR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

