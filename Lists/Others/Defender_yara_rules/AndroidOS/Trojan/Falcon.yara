rule Trojan_AndroidOS_Falcon_A_2147835741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Falcon.A"
        threat_id = "2147835741"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Falcon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/ActivityGetSMSFaApp;" ascii //weight: 1
        $x_1_2 = "/ActivitySpamSmsFaApp;" ascii //weight: 1
        $x_1_3 = "/ActivityStartUSSDFaApp;" ascii //weight: 1
        $x_1_4 = "/ActivityFakeAppStartFaApp;" ascii //weight: 1
        $x_1_5 = "/ServiceAccessibilityFaApp;" ascii //weight: 1
        $x_1_6 = "/ActivityStartInjectionFaApp;" ascii //weight: 1
        $x_1_7 = "/ServiceInteractionServerFaApp;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

