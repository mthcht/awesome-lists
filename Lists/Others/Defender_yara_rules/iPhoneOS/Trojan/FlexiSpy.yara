rule Trojan_iPhoneOS_FlexiSpy_A_2147751517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/FlexiSpy.A!MTB"
        threat_id = "2147751517"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "FlexiSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/var/.lsalcore/shares/" ascii //weight: 2
        $x_1_2 = "%@/etc/ForceOut.plist" ascii //weight: 1
        $x_1_3 = "MSFSPUtils" ascii //weight: 1
        $x_1_4 = "captureStarted:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_iPhoneOS_FlexiSpy_B_2147751798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/FlexiSpy.B!MTB"
        threat_id = "2147751798"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "FlexiSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killall MobileMail" ascii //weight: 1
        $x_1_2 = "%@/etc/ForceOut.plist" ascii //weight: 1
        $x_1_3 = "deviphonev2t@gmail.com" ascii //weight: 1
        $x_1_4 = "setMCameraStartCapture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

