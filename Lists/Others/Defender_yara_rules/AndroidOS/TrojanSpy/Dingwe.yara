rule TrojanSpy_AndroidOS_Dingwe_B_2147850115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Dingwe.B!MTB"
        threat_id = "2147850115"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Dingwe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getinboxsms" ascii //weight: 1
        $x_1_2 = "/KeyLog.txt" ascii //weight: 1
        $x_1_3 = "com.connect" ascii //weight: 1
        $x_1_4 = "Contacts.txt" ascii //weight: 1
        $x_1_5 = "/new-upload.php" ascii //weight: 1
        $x_1_6 = "Sms_Sent.txt" ascii //weight: 1
        $x_1_7 = "deletecalllognumber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

