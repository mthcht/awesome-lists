rule TrojanSpy_AndroidOS_Infostealer_O_2147787557_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Infostealer.O!MTB"
        threat_id = "2147787557"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "config_send_mail" ascii //weight: 1
        $x_1_2 = "getPhone_number" ascii //weight: 1
        $x_1_3 = "sms_phone_number" ascii //weight: 1
        $x_1_4 = "sendSmsData" ascii //weight: 1
        $x_1_5 = "sms_id_current" ascii //weight: 1
        $x_1_6 = "SmsInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Infostealer_J_2147825417_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Infostealer.J!MTB"
        threat_id = "2147825417"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getAllContacts" ascii //weight: 1
        $x_1_2 = "WorkNow" ascii //weight: 1
        $x_1_3 = "showContacts" ascii //weight: 1
        $x_1_4 = "msgBody" ascii //weight: 1
        $x_1_5 = "isMobileNO" ascii //weight: 1
        $x_1_6 = "postData" ascii //weight: 1
        $x_1_7 = "getList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Infostealer_S_2147828400_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Infostealer.S!MTB"
        threat_id = "2147828400"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "getContactList" ascii //weight: 1
        $x_1_2 = {2f 70 61 79 [0-5] 2e 70 68 70 3f 6e 61 6d 65 3d}  //weight: 1, accuracy: Low
        $x_1_3 = "/messagebot.php" ascii //weight: 1
        $x_1_4 = "com-zeroone-divaraop-SmsReceiver" ascii //weight: 1
        $x_1_5 = "getMessageBody" ascii //weight: 1
        $x_1_6 = "has_phone_number" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Infostealer_V_2147828401_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Infostealer.V!MTB"
        threat_id = "2147828401"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSoutObserver" ascii //weight: 1
        $x_1_2 = "lOCK_OPENED" ascii //weight: 1
        $x_1_3 = "ActivityTracker" ascii //weight: 1
        $x_1_4 = "restartmain" ascii //weight: 1
        $x_1_5 = "android.os.callreceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

