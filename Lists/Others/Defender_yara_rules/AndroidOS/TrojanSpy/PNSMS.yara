rule TrojanSpy_AndroidOS_PNSMS_A_2147798195_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/PNSMS.A!MTB"
        threat_id = "2147798195"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "PNSMS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/data/Message.oliver" ascii //weight: 1
        $x_1_2 = "ResumableSub_Sending_sms" ascii //weight: 1
        $x_1_3 = "/data/Numbers.oliver" ascii //weight: 1
        $x_1_4 = {2f 70 61 6e 65 6c 2e 70 68 70 3f 73 6d 73 [0-4] 3d 67 65 74}  //weight: 1, accuracy: Low
        $x_1_5 = "/panel.php?uploadsms=" ascii //weight: 1
        $x_1_6 = "/panel.php?uploadcon=" ascii //weight: 1
        $x_1_7 = "oliverhome.ml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

