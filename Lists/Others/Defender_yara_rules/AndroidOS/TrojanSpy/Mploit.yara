rule TrojanSpy_AndroidOS_Mploit_A_2147753536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Mploit.A!MTB"
        threat_id = "2147753536"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Mploit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "content://call_log/calls" ascii //weight: 1
        $x_1_2 = "com.etechd.l3mon" ascii //weight: 1
        $x_1_3 = "&manf=" ascii //weight: 1
        $x_1_4 = "contactsList" ascii //weight: 1
        $x_1_5 = "com.support.appz" ascii //weight: 1
        $x_1_6 = "Malformed close payload " ascii //weight: 1
        $x_1_7 = "package:com.remote.app" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

