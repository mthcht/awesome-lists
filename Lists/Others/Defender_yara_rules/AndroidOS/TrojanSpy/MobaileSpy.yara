rule TrojanSpy_AndroidOS_MobaileSpy_A_2147826539_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/MobaileSpy.A!MTB"
        threat_id = "2147826539"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "MobaileSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "com.sasa.spy" ascii //weight: 1
        $x_1_2 = {6b 73 61 2d 73 65 66 2e 63 6f 6d 2f 48 61 63 6b [0-5] 4d 6f 62 61 69 6c 65}  //weight: 1, accuracy: Low
        $x_1_3 = "userSMS" ascii //weight: 1
        $x_1_4 = "userContacts" ascii //weight: 1
        $x_1_5 = "usercalllog" ascii //weight: 1
        $x_1_6 = "/AddAllLogCall.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

