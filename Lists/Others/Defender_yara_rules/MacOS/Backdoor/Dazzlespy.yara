rule Backdoor_MacOS_Dazzlespy_A_2147812329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Dazzlespy.A"
        threat_id = "2147812329"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Dazzlespy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "88.218.192.128:5633" ascii //weight: 1
        $x_1_2 = "Keychain Data: %@" ascii //weight: 1
        $x_1_3 = "%@/.local/softwareupdate" ascii //weight: 1
        $x_1_4 = "/com.apple.softwareupdate.plist" ascii //weight: 1
        $x_1_5 = ".local/security/keystealDaemon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

