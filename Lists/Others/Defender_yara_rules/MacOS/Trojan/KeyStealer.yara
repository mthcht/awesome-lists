rule Trojan_MacOS_KeyStealer_A_2147837264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/KeyStealer.A"
        threat_id = "2147837264"
        type = "Trojan"
        platform = "MacOS: "
        family = "KeyStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/MobileDevice/Provisioning Profiles" ascii //weight: 1
        $x_1_2 = "/Library/LaunchDaemons/com.apple.googlechrome.plist" ascii //weight: 1
        $x_1_3 = "xattr -c -r %@" ascii //weight: 1
        $x_1_4 = "chmod +x %@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

