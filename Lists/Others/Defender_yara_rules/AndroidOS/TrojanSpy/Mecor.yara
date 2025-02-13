rule TrojanSpy_AndroidOS_Mecor_A_2147832929_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mecor.A!MTB"
        threat_id = "2147832929"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mecor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "alarm/?from_app=" ascii //weight: 1
        $x_1_2 = "hide_gps_progress" ascii //weight: 1
        $x_1_3 = "cocoam.co.kr/api/" ascii //weight: 1
        $x_1_4 = "android_app_check_user_info" ascii //weight: 1
        $x_1_5 = {63 6f 6d 2f [0-19] 2f [0-32] 2f 6d 61 69 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

