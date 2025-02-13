rule TrojanSpy_AndroidOS_Bian_A_2147783409_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bian.A"
        threat_id = "2147783409"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bian"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "InjComponentBuilderImpl" ascii //weight: 2
        $x_2_2 = "updateStockInjectsList" ascii //weight: 2
        $x_1_3 = "iLockStateListener" ascii //weight: 1
        $x_1_4 = "services_playProtect" ascii //weight: 1
        $x_1_5 = "requestSmsAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Bian_A_2147805862_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Bian.A!MTB"
        threat_id = "2147805862"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Bian"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sorry!need8money[for`food" ascii //weight: 1
        $x_1_2 = "AndroidBot" ascii //weight: 1
        $x_1_3 = "onInjectNotificationReceived" ascii //weight: 1
        $x_1_4 = "Screencast" ascii //weight: 1
        $x_1_5 = "deleteSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

