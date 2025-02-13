rule Trojan_MacOS_Dazzlespy_A_2147811312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Dazzlespy.A!MTB"
        threat_id = "2147811312"
        type = "Trojan"
        platform = "MacOS: "
        family = "Dazzlespy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "88.218.192.128:5633" ascii //weight: 1
        $x_1_2 = "com.apple.softwareupdate.plist" ascii //weight: 1
        $x_1_3 = "osxrk" ascii //weight: 1
        $x_1_4 = "restartCMD" ascii //weight: 1
        $x_1_5 = "uninstall" ascii //weight: 1
        $x_1_6 = "acceptFileInfo" ascii //weight: 1
        $x_1_7 = "searchFile" ascii //weight: 1
        $x_1_8 = "/.local/softwareupdate" ascii //weight: 1
        $x_1_9 = "killall -9 softwareupdate" ascii //weight: 1
        $x_1_10 = "/pangu/create_source/poke/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

