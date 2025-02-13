rule Trojan_AndroidOS_ADSpy_TA_2147808759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/ADSpy.TA!MTB"
        threat_id = "2147808759"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "ADSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "handleHack" ascii //weight: 1
        $x_1_2 = "hk59ynad" ascii //weight: 1
        $x_1_3 = "CallLogCountCollector" ascii //weight: 1
        $x_1_4 = "DeviceInfoExtraEvaluator" ascii //weight: 1
        $x_1_5 = "InstallationTracker" ascii //weight: 1
        $x_1_6 = "Lcom/clare/facebookprofilehacker/MainActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

