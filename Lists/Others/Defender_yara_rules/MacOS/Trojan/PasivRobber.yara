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
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 73 fe 48 89 f7 48 c1 ef 02 42 0f b6 0c 0f 41 88 4c 05 00 c1 e6 04 83 e6 30 0f b6 4b ff 48 89 cf 48 c1 ef 04 48 09 f7 41 0f b6 14 39 41 88 54 05 01 83 e1 0f 0f b6 13 48 89 d6 48 c1 ee 06 48 8d 0c 8e 41 0f b6 0c 09 41 88 4c 05 02 83 e2 3f 42 0f b6 0c 0a 41 88 4c 05 03 48 83 c0 04 48 83 c3 03 49 39 c0}  //weight: 1, accuracy: High
        $x_1_2 = {c1 ee 0c 40 80 ce e0 40 88 30 89 d6 c1 ee 06 40 80 e6 3f 40 80 ce 80 40 88 70 01 80 e2 3f 80 ca 80 88 50 02 ba 03 00 00 00 48 01 d0 48 83 c1 02 48 89 cf 48 89 f9 4c 39 e7}  //weight: 1, accuracy: High
        $x_1_3 = "TBL_AF_WEB_QQBROWSER_DOWNLOAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
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
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 fd 42 d3 09 05 00 91 2a f1 7e 92 88 0a 0a 8b 8b 22 00 91 00 e4 00 6f 01 04 04 0f 02 25 00 0f 0c f0 9f 52 83 0d 04 0e 8c 00 80 52 84 0d 08 4e 2c 00 80 52 85 0d 08 4e 4c 00 80 52 86 0d 08 4e e7 07 03 2f 6c 00 80 52 91 0d 08 4e ec 03 0a aa 10 e4 00 6f}  //weight: 1, accuracy: High
        $x_1_2 = {09 15 40 38 4a 6b 69 38 ca ff 1f 37 0a 05 00 d1 3f b5 00 71 08 01 8a 9a 09 01 40 39 49 04 00 b4 2a c1 00 d1 5f 25 00 f1 09 01 00 54 3f b9 00 71 a1 03 00 54 09 05 40 39 29 c1 00 d1 3f 25 00 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

