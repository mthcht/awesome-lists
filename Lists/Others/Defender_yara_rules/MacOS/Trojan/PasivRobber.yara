rule Trojan_MacOS_PasivRobber_A_2147940022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PasivRobber.A!MTB"
        threat_id = "2147940022"
        type = "Trojan"
        platform = "MacOS: "
        family = "PasivRobber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 73 fe 48 89 f7 48 c1 ef 02 42 0f b6 0c 0f 41 88 4c 05 00 c1 e6 04 83 e6 30 0f b6 4b ff 48 89 cf 48 c1 ef 04 48 09 f7 41 0f b6 14 39 41 88 54 05 01 83 e1 0f 0f b6 13 48 89 d6 48 c1 ee 06 48 8d 0c 8e 41 0f b6 0c 09 41 88 4c 05 02 83 e2 3f 42 0f b6 0c 0a 41 88 4c 05 03 48 83 c0 04 48 83 c3 03 49 39 c0}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 41 57 41 56 41 55 41 54 53 48 83 ec 58 8b 4e 30 85 c9 0f 8e 62 02 00 00 49 89 f7 48 8b 1a 48 8b 72 08 48 89 f7 b8 01 00 00 00 48 29 df 0f 84 49 02 00 00 48 89 55 80 45 31 f6 4c 89 7d c8}  //weight: 1, accuracy: High
        $x_1_3 = {41 8b 4f 30 41 01 ce 48 8b 45 80 48 8b 18 48 8b 70 08 48 89 f7 48 29 df 4c 39 f7 0f 86 06 02 00 00 0f 57 c0 0f 29 45 a0 48 c7 45 b0 00 00 00 00 85 c9}  //weight: 1, accuracy: High
        $x_1_4 = "TBL_AF_WEB_QQBROWSER_DOWNLOAD" ascii //weight: 1
        $x_1_5 = "TBL_AF_WEB_LINUX_FIREFOX_SEARCH" ascii //weight: 1
        $x_1_6 = "TBL_AF_WEB_CHROME_LOGIN_DATA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MacOS_PasivRobber_B_2147940023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PasivRobber.B!MTB"
        threat_id = "2147940023"
        type = "Trojan"
        platform = "MacOS: "
        family = "PasivRobber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e2 0d 7f 29 e4 15 c2 28 42 08 c0 5a 63 08 c0 5a 84 08 c0 5a a5 08 c0 5a 5f fc 1f 71 e6 97 9f 1a 5f 00 20 71 e7 27 9f 1a 7f fc 1f 71 f4 97 9f 1a 7f 00 20 71 f7 27 9f 1a 9f fc 1f 71 f8 97 9f 1a 9f 00 20 71 f9 27 9f 1a bf fc 1f 71 fc 97 9f 1a bf 00 20 71 fe 27 9f 1a a5 00 02 71 09 26 9f 9a 84 00 02 71 0a 26 9f 9a 63 00 02 71 1b 26 9f 9a 42 00 02 71 42 7c 07 53 13 26 9f 9a 5f fc 07 71 62 7c 07 53 e3 27 9f 1a 5f fc 07 71 82 7c 07 53 e4 27 9f 1a 5f fc 07 71}  //weight: 1, accuracy: High
        $x_1_2 = {4d e1 5f 38 ae fd 42 d3 8e 69 6e 38 6f 01 08 8b ee f1 1f 38 ad 6d 1c 53 ad 05 7c 92 4e f1 5f 38 ad 11 4e aa 8d 69 6d 38 ed 01 00 39 cd 75 1e 53 ad 0d 7e 92 4e 35 40 38 ad 19 4e aa 8d 69 6d 38 ed 05 00 39 cd 15 40 92 8d 69 6d 38 ed 09 00 39 08 11 00 91 3f 01 08 eb}  //weight: 1, accuracy: High
        $x_1_3 = {fc 57 00 a9 f3 53 03 29 f7 13 00 f9 0d 00 80 d2 0e 00 80 d2 0c 00 80 d2 0b 00 80 d2 08 fd 42 d3 08 05 00 91 f5 03 08 aa 09 f1 7e 92 c8 0a 09 8b f6 0b 00 f9 cf 22 00 91 f6 03 09 aa 90 00 80 52 51 00 80 52 60 00 80 52 e1 03 09 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_PasivRobber_C_2147943464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PasivRobber.C!MTB"
        threat_id = "2147943464"
        type = "Trojan"
        platform = "MacOS: "
        family = "PasivRobber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WXRobber" ascii //weight: 1
        $x_1_2 = "com.myam.plist" ascii //weight: 1
        $x_1_3 = "GetScreenShot" ascii //weight: 1
        $x_1_4 = "libIMKeyTool" ascii //weight: 1
        $x_1_5 = "RemoteMsgManager" ascii //weight: 1
        $x_1_6 = "GetClipboardInfos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

