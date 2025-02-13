rule Trojan_AndroidOS_Tekwon_B_2147812806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Tekwon.B!MTB"
        threat_id = "2147812806"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Tekwon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SysBrowserObserver" ascii //weight: 1
        $x_1_2 = "AppFakeActivity" ascii //weight: 1
        $x_1_3 = "doUpdateVisitedHistory" ascii //weight: 1
        $x_1_4 = "MonitorPhoneCall" ascii //weight: 1
        $x_1_5 = "DeleteCallContent" ascii //weight: 1
        $x_1_6 = "SMSSapmObserver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

