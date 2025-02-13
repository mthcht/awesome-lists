rule Ransom_AndroidOS_Simplocker_A_2147758240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Simplocker.A!MTB"
        threat_id = "2147758240"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Simplocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f 61 64 75 6c 74 2f 66 72 65 65 2f 68 64 2f [0-32] 76 69 64 65 6f 2f 70 6c 61 79 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = "video/player/DeviceAdminChecker" ascii //weight: 1
        $x_1_3 = "DecryptService" ascii //weight: 1
        $x_1_4 = "WakeLock" ascii //weight: 1
        $x_1_5 = "RunningTaskInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

