rule TrojanSpy_AndroidOS_Ewalls_T_2147782642_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ewalls.T!MTB"
        threat_id = "2147782642"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ewalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 70 69 2e 62 69 74 2e 6c 79 2f 73 68 6f 72 74 65 6e 3f 76 65 72 73 69 6f 6e 3d [0-6] 26 6c 6f 67 69 6e 3d 65 77 61 6c 6c 70 61 70 65 72 26 61 70 69 4b 65 79 3d [0-53] 26 6c 6f 6e 67 55 72 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "sendDeviceInfos" ascii //weight: 1
        $x_1_3 = "/api/wallpapers/log/action_log?typee" ascii //weight: 1
        $x_1_4 = "ysler.com" ascii //weight: 1
        $x_1_5 = "appscolor.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Ewalls_A_2147829043_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ewalls.A!MTB"
        threat_id = "2147829043"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ewalls"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 70 69 2e 62 69 74 2e 6c 79 2f 73 68 6f 72 74 65 6e 3f 76 65 72 73 69 6f 6e 3d [0-6] 26 6c 6f 67 69 6e 3d 65 77 61 6c 6c 70 61 70 65 72 26 61 70 69 4b 65 79 3d [0-64] 26 6c 6f 6e 67 55 72 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "sendDeviceInfos" ascii //weight: 1
        $x_1_3 = "/log/action_log?typee" ascii //weight: 1
        $x_1_4 = "/log/device_info?" ascii //weight: 1
        $x_1_5 = "wps.appscolor.net" ascii //weight: 1
        $x_1_6 = "log.ysler.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

