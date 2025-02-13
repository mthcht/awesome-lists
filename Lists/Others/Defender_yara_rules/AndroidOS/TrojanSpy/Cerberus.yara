rule TrojanSpy_AndroidOS_Cerberus_D_2147770327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Cerberus.D!MTB"
        threat_id = "2147770327"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "grabbing_lockpattern" ascii //weight: 1
        $x_1_2 = "grabbing_google_authenticator" ascii //weight: 1
        $x_1_3 = "run_admin_device" ascii //weight: 1
        $x_1_4 = "sms_mailing_phonebook" ascii //weight: 1
        $x_1_5 = "send_mailing_sms" ascii //weight: 1
        $x_1_6 = "rat_connect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Cerberus_E_2147781851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Cerberus.E!MTB"
        threat_id = "2147781851"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {21 70 23 00 a9 00 12 01 21 72 35 21 34 00 52 62 ?? 00 d8 02 02 01 d4 22 00 01 59 62 ?? 00 52 62 ?? 00 54 63 ?? 00 52 64 ?? 00 44 05 03 04 b0 52 d4 22 00 01 59 62 ?? 00 52 62 ?? 00 71 30 ?? ?? 24 03 54 62 ?? 00 52 63 ?? 00 44 03 02 03 52 64 ?? 00 44 04 02 04 b0 43 d4 33 00 01 44 02 02 03 48 03 07 01 b7 32 8d 22 4f 02 00 01 d8 01 01 01 28 cc 11 00}  //weight: 2, accuracy: Low
        $x_1_2 = "send_log_injects" ascii //weight: 1
        $x_1_3 = "openAccessibilityService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Cerberus_G_2147794063_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Cerberus.G"
        threat_id = "2147794063"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "action=sendListPhoneNumbers&data=" ascii //weight: 2
        $x_2_2 = "sendSmsLogs&data=" ascii //weight: 2
        $x_2_3 = "Send Data Injection to Server:" ascii //weight: 2
        $x_2_4 = "logsContacts" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Cerberus_H_2147794188_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Cerberus.H"
        threat_id = "2147794188"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "||youNeedMoreResources||" ascii //weight: 2
        $x_2_2 = "LOADING INJECT++++++++" ascii //weight: 2
        $x_1_3 = "sms_sdk_Q" ascii //weight: 1
        $x_1_4 = "run_king_service" ascii //weight: 1
        $x_1_5 = "HideInject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Cerberus_B_2147837782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Cerberus.B!MTB"
        threat_id = "2147837782"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Cerberus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "whileStartUpdateInection" ascii //weight: 1
        $x_1_2 = "action=sendKeylogger" ascii //weight: 1
        $x_1_3 = "lockDevice" ascii //weight: 1
        $x_1_4 = "listAppGrabCards" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

