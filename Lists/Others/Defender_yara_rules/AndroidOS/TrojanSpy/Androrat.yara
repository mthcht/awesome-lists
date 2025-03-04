rule TrojanSpy_AndroidOS_Androrat_B_2147754095_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Androrat.B!MTB"
        threat_id = "2147754095"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Androrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 63 6f 6d 2f [0-8] 2f 61 70 70 63 6f 64 65 2f 61 70 70 63 6f 64 65 2f 4d 61 69 6e 41 63 74 69 76 69 74 79}  //weight: 2, accuracy: Low
        $x_1_2 = "Lcom/chagall/screenshot" ascii //weight: 1
        $x_1_3 = "camvdo=camvdo" ascii //weight: 1
        $x_1_4 = "smsMoniter" ascii //weight: 1
        $x_1_5 = "Lcom/chagall/notificationlisten" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Androrat_C_2147812788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Androrat.C!MTB"
        threat_id = "2147812788"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Androrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f [0-8] 2f 61 70 70 63 6f 64 65 2f 61 70 70 63 6f 64 65 2f 4d 61 69 6e 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
        $x_1_2 = "CallRecording" ascii //weight: 1
        $x_1_3 = "listCallLog" ascii //weight: 1
        $x_1_4 = "smsMoniter" ascii //weight: 1
        $x_1_5 = "appcode/ScreenShot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Androrat_D_2147828950_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Androrat.D!MTB"
        threat_id = "2147828950"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Androrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InterceptCall" ascii //weight: 1
        $x_1_2 = "callLogObserver" ascii //weight: 1
        $x_1_3 = "InterceptSms" ascii //weight: 1
        $x_1_4 = "BootComplateBroadcast" ascii //weight: 1
        $x_1_5 = "MONITOR_CALL_RECORDING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

