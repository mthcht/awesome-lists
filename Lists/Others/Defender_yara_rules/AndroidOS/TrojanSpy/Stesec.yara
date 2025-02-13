rule TrojanSpy_AndroidOS_Stesec_A_2147783172_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Stesec.A!MTB"
        threat_id = "2147783172"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Stesec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SecuritySmsExecSend" ascii //weight: 2
        $x_2_2 = "SecuritySmsService" ascii //weight: 2
        $x_2_3 = "ExecSendSms" ascii //weight: 2
        $x_1_4 = "/data/emode/smsmode.conf" ascii //weight: 1
        $x_1_5 = "antifakesms" ascii //weight: 1
        $x_1_6 = "getZteSmsInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

