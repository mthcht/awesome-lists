rule TrojanSpy_AndroidOS_SmsTheif_D_2147815859_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsTheif.D!MTB"
        threat_id = "2147815859"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsTheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getSmsFromPhone" ascii //weight: 1
        $x_1_2 = "Lchina/gov/svngs/SmSserver" ascii //weight: 1
        $x_1_3 = "getInfo" ascii //weight: 1
        $x_1_4 = "zjjson" ascii //weight: 1
        $x_1_5 = "pcdufavvbzkbzfsb" ascii //weight: 1
        $x_1_6 = "receiveTime" ascii //weight: 1
        $x_1_7 = "GetNetIp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsTheif_AH_2147827524_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsTheif.AH!MTB"
        threat_id = "2147827524"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsTheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/sdksms/sms/sms.do" ascii //weight: 1
        $x_1_2 = "/sdksales/sync/getan.do" ascii //weight: 1
        $x_1_3 = "SmsReciver-Reply-huifutask" ascii //weight: 1
        $x_1_4 = "SmsReciver-Upload" ascii //weight: 1
        $x_1_5 = "SmsReciver-Shield-bret" ascii //weight: 1
        $x_1_6 = {53 6d 73 54 61 73 6b [0-5] 64 65 6c 53 6d 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsTheif_E_2147829042_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsTheif.E!MTB"
        threat_id = "2147829042"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsTheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "appSmsLogger" ascii //weight: 1
        $x_1_2 = "sendmultisms" ascii //weight: 1
        $x_1_3 = "LightZer0" ascii //weight: 1
        $x_1_4 = "sajjad4580" ascii //weight: 1
        $x_1_5 = "UploadSms" ascii //weight: 1
        $x_1_6 = "sendMultipartTextSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsTheif_G_2147839369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsTheif.G!MTB"
        threat_id = "2147839369"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsTheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rlst_srvctrl" ascii //weight: 1
        $x_1_2 = "cnfinfo_cmd_keyword" ascii //weight: 1
        $x_1_3 = "reminfo_count=" ascii //weight: 1
        $x_1_4 = "getOriginatingAddress" ascii //weight: 1
        $x_1_5 = "config_fee_item" ascii //weight: 1
        $x_1_6 = "config_fee_wap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_SmsTheif_F_2147840510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsTheif.F!MTB"
        threat_id = "2147840510"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsTheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com.khins.jtexpress" ascii //weight: 1
        $x_1_2 = {61 70 69 2e 78 6a 61 6b 75 76 2e 74 6b 2f [0-32] 2f 69 6e 73 74 61 6c 6c 65 64 2e 70 68 70 3f 64 65 76 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {61 70 69 2e 78 6a 61 6b 75 76 2e 74 6b 2f [0-32] 3f 6d 73 67 3d}  //weight: 1, accuracy: Low
        $x_1_4 = "ReceiveSms" ascii //weight: 1
        $x_1_5 = "getOriginatingAddress" ascii //weight: 1
        $x_1_6 = "getMessageBody" ascii //weight: 1
        $x_1_7 = "android.permission.RECEIVE_SMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule TrojanSpy_AndroidOS_SmsTheif_H_2147846500_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsTheif.H!MTB"
        threat_id = "2147846500"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsTheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Max_Sms_Time" ascii //weight: 1
        $x_1_2 = "Last_Sms_Key" ascii //weight: 1
        $x_1_3 = "XMS.APP" ascii //weight: 1
        $x_1_4 = "f8ab2ceca9163724b6d126aea9620339" ascii //weight: 1
        $x_1_5 = "getSimSerialNumber" ascii //weight: 1
        $x_1_6 = "getOriginatingAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

