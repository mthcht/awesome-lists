rule Trojan_AndroidOS_Fidall_AS_2147781466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Fidall.AS!MTB"
        threat_id = "2147781466"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Fidall"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMS READER" ascii //weight: 1
        $x_1_2 = "EMAIL_OPERATION_CODE" ascii //weight: 1
        $x_1_3 = "abonent.findandcall.com" ascii //weight: 1
        $x_1_4 = "CALL_LOG" ascii //weight: 1
        $x_1_5 = "recent_calls" ascii //weight: 1
        $x_1_6 = "INCOMING_CALLS_TABLE_NAME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

