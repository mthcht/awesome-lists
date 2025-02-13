rule MonitoringTool_AndroidOS_AndroRat_199201_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/AndroRat"
        threat_id = "199201"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "AndroRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "android.permission.ACCESS_FINE_LOCATION" wide //weight: 1
        $x_1_2 = "android.permission.ACCESS_NETWORK_STATE" wide //weight: 1
        $x_1_3 = "android.permission.CALL_PHONE" wide //weight: 1
        $x_1_4 = "android.permission.CAMERA" wide //weight: 1
        $x_1_5 = "android.permission.INTERNET" wide //weight: 1
        $x_1_6 = "android.permission.PROCESS_OUTGOING_CALLS" wide //weight: 1
        $x_1_7 = "android.permission.READ_CONTACTS" wide //weight: 1
        $x_1_8 = "android.permission.READ_PHONE_STATE" wide //weight: 1
        $x_1_9 = "android.permission.READ_SMS" wide //weight: 1
        $x_1_10 = "android.permission.RECEIVE_BOOT_COMPLETED" wide //weight: 1
        $x_1_11 = "android.permission.RECEIVE_SMS" wide //weight: 1
        $x_1_12 = "android.permission.RECORD_AUDIO" wide //weight: 1
        $x_1_13 = "android.permission.SEND_SMS" wide //weight: 1
        $x_1_14 = "android.permission.VIBRATE" wide //weight: 1
        $x_1_15 = "android.permission.WRITE_EXTERNAL_STORAGE" wide //weight: 1
        $x_1_16 = "Building Injected APK." wide //weight: 1
        $x_1_17 = "Injecting IP & Port." wide //weight: 1
        $x_1_18 = "Injecting AndroRat Source." wide //weight: 1
        $x_1_19 = "deceptiveengineeringrocks" wide //weight: 1
        $x_1_20 = "AndroRat Binder - [ deceptiveengineering.info ]" wide //weight: 1
        $x_1_21 = "AndroRat_Binder.Form1.resources" ascii //weight: 1
        $x_1_22 = "AndroRat_Binder.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_AndroRat_199201_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/AndroRat"
        threat_id = "199201"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "AndroRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Start SMS monitoring" ascii //weight: 1
        $x_1_2 = "*Androrat.Client.storage" ascii //weight: 1
        $x_1_3 = "DATA_MONITOR_CALL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

