rule Trojan_iPhoneOS_AdStealer_A_2147755838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/AdStealer.A!MTB"
        threat_id = "2147755838"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "AdStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.bitsimple.SimplyBTC" ascii //weight: 1
        $x_1_2 = "/Library/LaunchDaemons/com.MakeALife.verifydp.plist" ascii //weight: 1
        $x_1_3 = "Applications/UFCPro.app/UFCPro" ascii //weight: 1
        $x_1_4 = "com.meoyeu.fd.plist" ascii //weight: 1
        $x_1_5 = "idfcp.dylib" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_iPhoneOS_AdStealer_B_2147755841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:iPhoneOS/AdStealer.B!MTB"
        threat_id = "2147755841"
        type = "Trojan"
        platform = "iPhoneOS: "
        family = "AdStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "namegenerator.plist" ascii //weight: 1
        $x_1_2 = "mobile/RRSout/DATA3folder" ascii //weight: 1
        $x_1_3 = "com.meoyeu.fd.plist" ascii //weight: 1
        $x_1_4 = "cydia://package/sudo" ascii //weight: 1
        $x_1_5 = "All backup files were deleted" ascii //weight: 1
        $x_1_6 = "killall -9 profiled" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

