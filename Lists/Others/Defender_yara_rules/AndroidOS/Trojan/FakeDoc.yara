rule Trojan_AndroidOS_FakeDoc_A_2147755398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeDoc.A"
        threat_id = "2147755398"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeDoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/zanalytics/sms/SmsReceiverService;" ascii //weight: 2
        $x_2_2 = "Sms_Receive_Tracking" ascii //weight: 2
        $x_2_3 = "handleSendSms - " ascii //weight: 2
        $x_1_4 = "mykills.dtke" ascii //weight: 1
        $x_1_5 = "Lcom/extend/battery/Splash;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_FakeDoc_B_2147842152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeDoc.B!MTB"
        threat_id = "2147842152"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeDoc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lcom/savebattery/killer/pro/EasyTaskKiller" ascii //weight: 2
        $x_2_2 = "getRecordedKilledApps" ascii //weight: 2
        $x_2_3 = "writeDeviceToDB" ascii //weight: 2
        $x_1_4 = "/Post/AddDevice" ascii //weight: 1
        $x_1_5 = "/Post/Traffic/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

