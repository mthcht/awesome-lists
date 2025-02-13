rule Trojan_MacOS_FakeCodecs_A_2147748663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/FakeCodecs.A!MTB"
        threat_id = "2147748663"
        type = "Trojan"
        platform = "MacOS: "
        family = "FakeCodecs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "stopApplicationsObserver" ascii //weight: 2
        $x_2_2 = "m_installationStepText" ascii //weight: 2
        $x_2_3 = "m_installationSecondoryText" ascii //weight: 2
        $x_1_4 = "removeOperaBlinkFromProfileWithPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

