rule TrojanSpy_AndroidOS_SmFrow_A_2147825034_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmFrow.A!MTB"
        threat_id = "2147825034"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmFrow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SmsInfoService" ascii //weight: 1
        $x_1_2 = "com.android.dobbin.MyServiceAA" ascii //weight: 1
        $x_1_3 = "is_location_update" ascii //weight: 1
        $x_1_4 = "is_get_message" ascii //weight: 1
        $x_1_5 = "is_contact_update" ascii //weight: 1
        $x_1_6 = {64 61 6d 69 6e 67 [0-4] 73 6d 73 20 63 6f 6e 74 65 6e 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SmFrow_B_2147830609_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmFrow.B!MTB"
        threat_id = "2147830609"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmFrow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.naruto.ted.uploadSms" ascii //weight: 1
        $x_1_2 = "delete from t_sms where id=?" ascii //weight: 1
        $x_1_3 = "smsWatch.db" ascii //weight: 1
        $x_1_4 = "SmsUploadTask" ascii //weight: 1
        $x_1_5 = "stringToGsm7BitPacked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmFrow_H_2147840512_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmFrow.H!MTB"
        threat_id = "2147840512"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmFrow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hp_state.php?telnum=" ascii //weight: 1
        $x_1_2 = "index.php?type=join&telnum=" ascii //weight: 1
        $x_1_3 = "ConnMachine" ascii //weight: 1
        $x_1_4 = "getLine1Number" ascii //weight: 1
        $x_1_5 = "server_url" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmFrow_C_2147846256_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmFrow.C!MTB"
        threat_id = "2147846256"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmFrow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSSpamReceiver" ascii //weight: 1
        $x_1_2 = "checkListenSMS" ascii //weight: 1
        $x_1_3 = "Spam_Address" ascii //weight: 1
        $x_1_4 = "smsrecommend.txt" ascii //weight: 1
        $x_1_5 = "SMS_Spam_Manager" ascii //weight: 1
        $x_1_6 = "SMS_Spam_Body" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

