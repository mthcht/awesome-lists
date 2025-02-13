rule Trojan_AndroidOS_SpyC23_A_2147793972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyC23.A"
        threat_id = "2147793972"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyC23"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "imsi_s_data" ascii //weight: 1
        $x_1_2 = "imsi_f_old_data" ascii //weight: 1
        $x_1_3 = "!CallRecording" ascii //weight: 1
        $x_1_4 = "!SmsRecording" ascii //weight: 1
        $x_1_5 = "skipProtectedAppsMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyC23_A_2147898350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyC23.A!MTB"
        threat_id = "2147898350"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyC23"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!CallRecording" ascii //weight: 1
        $x_1_2 = "StUpoodService" ascii //weight: 1
        $x_1_3 = "!SmsRecording" ascii //weight: 1
        $x_1_4 = "Call_History_" ascii //weight: 1
        $x_1_5 = "SMS_KEY_GET_DATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

