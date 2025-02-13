rule Trojan_MacOS_Sofacy_A_2147745302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Sofacy.A!MTB"
        threat_id = "2147745302"
        type = "Trojan"
        platform = "MacOS: "
        family = "Sofacy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Library/LaunchAgents/com.apple.updater.plist" ascii //weight: 1
        $x_1_2 = "<string>/Users/Shared/dufh</string>" ascii //weight: 1
        $x_1_3 = "/Users/Shared/start.sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Sofacy_A_2147745302_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Sofacy.A!MTB"
        threat_id = "2147745302"
        type = "Trojan"
        platform = "MacOS: "
        family = "Sofacy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 8d 48 fd ff ff 31 d2 89 d7 4c 8d 85 58 fd ff ff 4c 8d 4d e0 89 45 ec 48 c7 85 48 fd ff ff 88 02 00 00 48 89 bd 40 fd ff ff 4c 89 cf 4c 89 c2 4c 8b 85 40 fd ff ff 4c 8b 8d 40 fd ff ff e8 90 25 00 00 89 85 54 fd ff ff 81 bd 54 fd ff ff 00 00 00 00 41 0f 94 c2 41 80 f2 01 41 80 e2 01 41 0f b6 c2 89 c1 48 81 f9 00 00 00 00 0f 84 1f 00 00 00 48 8d 3d 93 2d 00 00 48 8d 35 9d 2d 00 00 ba 21 00 00 00 48 8d 0d c7 2d 00 00 e8 76 24 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "LoaderWinApi/LoaderWinApi/main.mm" ascii //weight: 1
        $x_1_3 = {4d 61 63 20 4f 53 20 58 20 2d 20 25 73 20 25 73 0a 55 73 65 72 20 6e 61 6d 65 20 2d 20 25 73 0a 09 09 09 09 09 09 50 72 6f 63 65 73 73 20 6c 69 73 74}  //weight: 1, accuracy: High
        $x_1_4 = "AmIBeingDebugged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

