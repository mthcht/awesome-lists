rule Backdoor_AndroidOS_Ahmyth_A_2147762309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Ahmyth.A!MTB"
        threat_id = "2147762309"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Ahmyth"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Display pop-up windows while running in the background" ascii //weight: 2
        $x_1_2 = "Screenshot" ascii //weight: 1
        $x_1_3 = "sendSMS" ascii //weight: 1
        $x_1_4 = "://pokpokpok-63573.portmap.host:63573?model=" ascii //weight: 1
        $x_1_5 = "content://call_log/calls" ascii //weight: 1
        $x_1_6 = "com/processor/pro/ScreenRecorderService" ascii //weight: 1
        $x_1_7 = "com.processor.pro.DeviceAdmin" ascii //weight: 1
        $x_1_8 = "Credentials.java" ascii //weight: 1
        $x_1_9 = {43 6c 69 63 6b 20 27 50 65 72 6d 69 73 73 69 6f 6e 73 27 [0-3] 45 6e 61 62 6c 65 20 41 4c 4c 20 70 65 72 6d 69 73 73 69 6f 6e 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

