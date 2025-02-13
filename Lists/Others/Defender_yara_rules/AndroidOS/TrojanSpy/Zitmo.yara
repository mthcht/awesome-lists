rule TrojanSpy_AndroidOS_Zitmo_A_2147787073_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Zitmo.A!MTB"
        threat_id = "2147787073"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Zitmo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LinkAntivirus" ascii //weight: 1
        $x_1_2 = "AntivirusEnabled" ascii //weight: 1
        $x_1_3 = "TotalHideSms" ascii //weight: 1
        $x_1_4 = "NEW_OUTGOING_CALL" ascii //weight: 1
        $x_1_5 = "smsAreHidden" ascii //weight: 1
        $x_1_6 = "Lcom/antivirus/kav/SmsReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

