rule TrojanSpy_iPhoneOS_LightRiver_A_2147752528_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:iPhoneOS/LightRiver.A!MTB"
        threat_id = "2147752528"
        type = "TrojanSpy"
        platform = "iPhoneOS: "
        family = "LightRiver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/mac/hs/dev/iosmm/light" ascii //weight: 1
        $x_1_2 = "GetPluginCommandID" ascii //weight: 1
        $x_1_3 = "GetCommandStatus" ascii //weight: 1
        $x_1_4 = "sendCommnadOver" ascii //weight: 1
        $x_1_5 = "\"cmd\":%d,\"status" ascii //weight: 1
        $x_1_6 = {3c 6b 65 79 3e 6b 65 79 63 68 61 69 6e 2d 61 63 63 65 73 73 2d 67 72 6f 75 70 73 3c 2f 6b 65 79 3e [0-84] 3c 61 72 72 61 79 3e [0-84] 3c 73 74 72 69 6e 67 3e 2a 3c 2f 73 74 72 69 6e 67 3e [0-84] 3c 2f 61 72 72 61 79 3e}  //weight: 1, accuracy: Low
        $x_1_7 = "getChromeHistoryPath" ascii //weight: 1
        $x_1_8 = "getSafariHistoryPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_iPhoneOS_LightRiver_B_2147831569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:iPhoneOS/LightRiver.B!MTB"
        threat_id = "2147831569"
        type = "TrojanSpy"
        platform = "iPhoneOS: "
        family = "LightRiver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "loadLight" ascii //weight: 1
        $x_1_2 = "/var/iolight" ascii //weight: 1
        $x_1_3 = "/bin/irc_loader" ascii //weight: 1
        $x_1_4 = "com.myapp.udid.light" ascii //weight: 1
        $x_1_5 = "sendCommnadOver" ascii //weight: 1
        $x_1_6 = {3c 6b 65 79 3e 6b 65 79 63 68 61 69 6e 2d 61 63 63 65 73 73 2d 67 72 6f 75 70 73 3c 2f 6b 65 79 3e [0-84] 3c 61 72 72 61 79 3e [0-84] 3c 73 74 72 69 6e 67 3e 2a 3c 2f 73 74 72 69 6e 67 3e [0-84] 3c 2f 61 72 72 61 79 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

