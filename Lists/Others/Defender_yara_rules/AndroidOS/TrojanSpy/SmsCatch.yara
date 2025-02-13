rule TrojanSpy_AndroidOS_SmsCatch_A_2147797851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SmsCatch.A!MTB"
        threat_id = "2147797851"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SmsCatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Android_SMS/installing.php" ascii //weight: 1
        $x_1_2 = "smssendingtest" ascii //weight: 1
        $x_1_3 = "arrayOfSmsMessage" ascii //weight: 1
        $x_1_4 = "numberchk1" ascii //weight: 1
        $x_1_5 = "catchSMS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

