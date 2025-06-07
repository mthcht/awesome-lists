rule TrojanSpy_AndroidOS_FakeCalls_K_2147815092_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeCalls.K!MTB"
        threat_id = "2147815092"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeCalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "videocloud.cn-hangzhou.log.aliyuncs.com" ascii //weight: 1
        $x_1_2 = "Call is hooked" ascii //weight: 1
        $x_1_3 = "onStartCommand" ascii //weight: 1
        $x_1_4 = "deleteSMS" ascii //weight: 1
        $x_1_5 = "KEY_EMAILS" ascii //weight: 1
        $x_1_6 = "KEY_TELECOMS_NAME1" ascii //weight: 1
        $x_1_7 = "KEY_UPLOAD_1" ascii //weight: 1
        $x_1_8 = "KEY_RECV_F" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule TrojanSpy_AndroidOS_FakeCalls_D_2147838521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeCalls.D!MTB"
        threat_id = "2147838521"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeCalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/device/gettransfer?number=" ascii //weight: 1
        $x_1_2 = "/device/getnumber?number=" ascii //weight: 1
        $x_1_3 = "/device/deviceendcall?imei=" ascii //weight: 1
        $x_1_4 = "&isStart=true&name=" ascii //weight: 1
        $x_1_5 = "upload_contracts" ascii //weight: 1
        $x_1_6 = "upload_sms" ascii //weight: 1
        $x_1_7 = "delete_calllog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_FakeCalls_E_2147841013_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeCalls.E!MTB"
        threat_id = "2147841013"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeCalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyLog_Main_" ascii //weight: 1
        $x_1_2 = "KEY_UPLOAD_1" ascii //weight: 1
        $x_1_3 = "KEY_SRC_NUMBER" ascii //weight: 1
        $x_1_4 = "KEY_TELECOMS_NAME1" ascii //weight: 1
        $x_1_5 = "deleteSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_FakeCalls_V_2147943034_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/FakeCalls.V!MTB"
        threat_id = "2147943034"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "FakeCalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com/wish/defaultcallservice/activity/ValidActivitySKV" ascii //weight: 1
        $x_1_2 = {81 01 02 14 02 8d 00 08 7f 6e 20 ?? 81 21 00 0c 02 6e 20 ?? 0a 12 00 14 02 07 01 08 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

