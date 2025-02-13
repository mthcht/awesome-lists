rule Trojan_AndroidOS_Acser_A_2147816506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Acser.A!MTB"
        threat_id = "2147816506"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Acser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/mycompany/myapp4/ABC" ascii //weight: 1
        $x_1_2 = "beginBindService" ascii //weight: 1
        $x_1_3 = "createMaskView" ascii //weight: 1
        $x_1_4 = "setServiceInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

