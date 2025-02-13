rule Backdoor_AndroidOS_Maxit_A_2147782825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Maxit.A!MTB"
        threat_id = "2147782825"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Maxit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c2dm.imaxter.net" ascii //weight: 1
        $x_1_2 = "SMS_ACCESS" ascii //weight: 1
        $x_1_3 = "directreplymobile" ascii //weight: 1
        $x_1_4 = "spGeoData" ascii //weight: 1
        $x_1_5 = "REPLY_BLOCK_NUMBER" ascii //weight: 1
        $x_1_6 = {4c 63 6f 6d 2f 6d 78 6d 6f 62 69 6c 65 [0-23] 50 75 73 68 41 64 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

