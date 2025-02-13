rule Trojan_AndroidOS_InfoStealer_O_2147777783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/InfoStealer.O!MTB"
        threat_id = "2147777783"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getThirdAppList" ascii //weight: 1
        $x_1_2 = "liveCallHistory" ascii //weight: 1
        $x_1_3 = "startStreaming" ascii //weight: 1
        $x_1_4 = "deleteThirdApp" ascii //weight: 1
        $x_1_5 = "startLiveRecord" ascii //weight: 1
        $x_1_6 = "smsList" ascii //weight: 1
        $x_1_7 = "&default_dialer_package_name=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_InfoStealer_S_2147795389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/InfoStealer.S"
        threat_id = "2147795389"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StartSalesStatisService" ascii //weight: 1
        $x_1_2 = "SEND_SMS_DELAY_TIME" ascii //weight: 1
        $x_1_3 = "ClickSimStateService" ascii //weight: 1
        $x_1_4 = "CHANNELCODE_FILENAME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_InfoStealer_A_2147808061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/InfoStealer.A"
        threat_id = "2147808061"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConnectionManager$100000001;" ascii //weight: 1
        $x_1_2 = "ConnectionManager$100000000;" ascii //weight: 1
        $x_1_3 = "getCallsLogs" ascii //weight: 1
        $x_1_4 = "startRecording" ascii //weight: 1
        $x_1_5 = "sendPhoto" ascii //weight: 1
        $x_1_6 = "sendVoice" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_AndroidOS_InfoStealer_F_2147808849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/InfoStealer.F"
        threat_id = "2147808849"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "uploadFirst" ascii //weight: 2
        $x_2_2 = "uploadSecond" ascii //weight: 2
        $x_2_3 = "fetchCUser" ascii //weight: 2
        $x_2_4 = "document.all.login.click();" ascii //weight: 2
        $x_1_5 = "shouldInterceptRequest" ascii //weight: 1
        $x_1_6 = "access_token=" ascii //weight: 1
        $x_1_7 = "device-based" ascii //weight: 1
        $x_1_8 = "com/?_rdr" ascii //weight: 1
        $x_1_9 = "adsmanager" ascii //weight: 1
        $x_1_10 = "c_user" ascii //weight: 1
        $x_1_11 = "saveStatus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_InfoStealer_B_2147811637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/InfoStealer.B"
        threat_id = "2147811637"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "InfoStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sentMicRecording" ascii //weight: 1
        $x_1_2 = "sentFrontCameraImage" ascii //weight: 1
        $x_1_3 = "getAllUserInfo" ascii //weight: 1
        $x_1_4 = "remainingWhatsAppImagesFiles" ascii //weight: 1
        $x_1_5 = "getAllSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

