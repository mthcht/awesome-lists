rule Trojan_AndroidOS_PounceSpy_A_2147931811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/PounceSpy.A!MTB"
        threat_id = "2147931811"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "PounceSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendBufferToDiscordAndClear" ascii //weight: 1
        $x_1_2 = "getSYSInfo" ascii //weight: 1
        $x_1_3 = "isAccessibilityServiceEnabledForPackage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

