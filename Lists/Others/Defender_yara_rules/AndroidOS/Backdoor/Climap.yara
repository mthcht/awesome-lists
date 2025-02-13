rule Backdoor_AndroidOS_Climap_A_2147811546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Climap.A!MTB"
        threat_id = "2147811546"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Climap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmsMonitorState" ascii //weight: 1
        $x_1_2 = "RecordOpenState" ascii //weight: 1
        $x_1_3 = "UploadContactRequest" ascii //weight: 1
        $x_1_4 = "UploadRecordFile" ascii //weight: 1
        $x_1_5 = "telephony.disable-call" ascii //weight: 1
        $x_1_6 = "generatePayload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_Climap_B_2147832962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Climap.B!MTB"
        threat_id = "2147832962"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Climap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.mynetsecure.chatsecure" ascii //weight: 1
        $x_1_2 = "AowsTempService2" ascii //weight: 1
        $x_1_3 = "@syria@internet@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

