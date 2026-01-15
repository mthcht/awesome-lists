rule Trojan_AndroidOS_Devixor_AMTB_2147961131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Devixor!AMTB"
        threat_id = "2147961131"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Devixor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "ir.devixor.app" ascii //weight: 10
        $x_1_2 = "foregroundService2.e0(arrayList, \"camera_" ascii //weight: 1
        $x_1_3 = "FCM_SERVICE" ascii //weight: 1
        $x_1_4 = "receive_url" ascii //weight: 1
        $x_1_5 = "SERVICE_GET_CMD" ascii //weight: 1
        $x_1_6 = "type=UPLOAD_IMAGE_ZIP&port=" ascii //weight: 1
        $x_1_7 = "GET_SCREENSHOTS" ascii //weight: 1
        $x_1_8 = "GET_SIM_SMS" ascii //weight: 1
        $x_1_9 = "GET_USSD_INFO" ascii //weight: 1
        $x_1_10 = "sms_alert" ascii //weight: 1
        $x_1_11 = "Received command:" ascii //weight: 1
        $x_1_12 = "Emulator detected" ascii //weight: 1
        $x_1_13 = "Debugger detected during runtime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

