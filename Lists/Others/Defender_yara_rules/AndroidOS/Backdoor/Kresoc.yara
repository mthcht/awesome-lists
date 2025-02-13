rule Backdoor_AndroidOS_Kresoc_T_2147782643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Kresoc.T!MTB"
        threat_id = "2147782643"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Kresoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f [0-4] 2f 70 6d 6f 6e 64 2f 72 65 66 2f 63 6f 6d 6d 61 6e 64 2f 52 65 6d 6f 74 65 53 65 74 4b 65 79 4c 6f 67 67 65 72 45 6e 61 62 6c 65}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 63 6f 6d 2f [0-6] 2f 72 65 6d 6f 74 65 63 6f 6e 74 72 6f 6c 2f 52 65 6d 6f 74 65 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "ProEnableSpyCallWithMonitor" ascii //weight: 1
        $x_1_4 = "chmod 755 /system/bin/app_process" ascii //weight: 1
        $x_1_5 = "PasswordCaptureManager" ascii //weight: 1
        $x_1_6 = "RemoteCameraActivity" ascii //weight: 1
        $x_1_7 = "CallLogCapture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

