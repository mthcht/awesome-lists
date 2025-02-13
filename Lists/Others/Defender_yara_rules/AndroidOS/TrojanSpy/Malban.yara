rule TrojanSpy_AndroidOS_Malban_A_2147767444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Malban.A!MTB"
        threat_id = "2147767444"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Malban"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "app/updateApp.php" ascii //weight: 1
        $x_1_2 = "setDefaultSmsApp" ascii //weight: 1
        $x_1_3 = "handleIncomingSMS" ascii //weight: 1
        $x_1_4 = "run-strIMEI:" ascii //weight: 1
        $x_1_5 = "calltransferredlist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

