rule TrojanSpy_AndroidOS_RewadSteal_A_2147842305_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/RewadSteal.A!MTB"
        threat_id = "2147842305"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "RewadSteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f 52 65 77 61 72 64 73 2f [0-16] 2f 61 70 69 43 6f 6e 74 72 6f 6c 6c 65 72}  //weight: 1, accuracy: Low
        $x_1_2 = "/root/api/user/step1" ascii //weight: 1
        $x_1_3 = "/root/api/user/sms" ascii //weight: 1
        $x_1_4 = "KEY_ETUSERNAME" ascii //weight: 1
        $x_1_5 = "addAutoStartup" ascii //weight: 1
        $x_1_6 = "SmsBroadcastReceiver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

