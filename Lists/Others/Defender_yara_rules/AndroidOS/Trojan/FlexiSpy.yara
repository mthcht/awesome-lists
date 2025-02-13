rule Trojan_AndroidOS_FlexiSpy_AS_2147781467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FlexiSpy.AS!MTB"
        threat_id = "2147781467"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FlexiSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deleteSMSContainingCommand" ascii //weight: 1
        $x_1_2 = "deleteCallsContainingCodeToRevealUI" ascii //weight: 1
        $x_1_3 = "Sending single-part message" ascii //weight: 1
        $x_1_4 = "MockPhoneInformation" ascii //weight: 1
        $x_1_5 = "eventIncomingCall" ascii //weight: 1
        $x_1_6 = "com.mobilefonex.mobilebackup.receivers.CallMonitor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

