rule TrojanSpy_AndroidOS_Dendroid_AS_2147780495_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Dendroid.AS!MTB"
        threat_id = "2147780495"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Dendroid"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deletecalllognumber" ascii //weight: 1
        $x_1_2 = "getcallhistory" ascii //weight: 1
        $x_1_3 = "getsentsms" ascii //weight: 1
        $x_1_4 = "RecordCalls" ascii //weight: 1
        $x_1_5 = "Screen Off Run Service" ascii //weight: 1
        $x_1_6 = "/mnt/sdcard/Download/update.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

