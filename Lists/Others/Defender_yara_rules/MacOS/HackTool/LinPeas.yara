rule HackTool_MacOS_LinPeas_A_2147923947_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/LinPeas.A!MTB"
        threat_id = "2147923947"
        type = "HackTool"
        platform = "MacOS: "
        family = "LinPeas"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0f 1f f8 fd 83 1f f8 fd 23 00 d1 00 00 80 b9 7f f1 00 94 fd 83 5f f8 fe 07 41 f8 c0 03 5f d6 fe 0f 1f f8 fd 83 1f f8 fd 23 00 d1 01 04 40 f9 02 10 80 b9 00 00 80 b9 78 f1 00 94 01 00 80 92 3f 00 00 eb 81 00 00 54 77 f1 00 94 00 00 80 b9 e0 03 00 cb}  //weight: 1, accuracy: High
        $x_1_2 = {81 0b 40 f9 e2 03 00 91 5f 00 01 eb c9 01 00 54 fe 0f 1e f8 fd 83 1f f8 fd 23 00 d1 81 13 40 f9 81 01 00 b5 40 07 40 f9 e0 07 00 f9 e0 17 40 f9 e0 0b 00 f9 3b 98 fe 97 fd 83 5f f8 fe 07 42 f8 c0 03 5f d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_LinPeas_B_2147937878_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/LinPeas.B!MTB"
        threat_id = "2147937878"
        type = "HackTool"
        platform = "MacOS: "
        family = "LinPeas"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/PEASS-ng/sh2bin/sh2bin.go" ascii //weight: 1
        $x_1_2 = "/opt/hostedtoolcache/go/1.17.0-rc1/x64/src/fmt/scan.go" ascii //weight: 1
        $x_1_3 = {48 8b 54 24 68 48 8b 74 24 50 48 8b 7c 24 48 48 8b 44 24 70 48 89 f9 48 8b 5c 24 30 49 39 c8 0f 8d 08 01 00 00 0f 83 2f 01 00 00 4c 89 44 24 28 49 c1 e0 04 4c 89 44 24 40 42 8b 1c 06 48 89 d0 e8 cc c9 04 00 48 89 84 24 90 00 00 00 48 8b 4c 24 40 48 8b 54 24 50 8b 5c 0a 04 48 8b 44 24 68}  //weight: 1, accuracy: High
        $x_1_4 = {49 89 d5 48 29 f2 48 83 c2 14 48 89 54 24 58 4c 8d 7e ec 4c 89 f8 49 c1 ff 3f 4c 21 fe 4c 8d bc 34 94 00 00 00 48 39 d7 73 3f 48 89 44 24 70 4c 89 bc 24 28 01 00 00 4c 89 6c 24 68 48 8d 05 bb a3 09 00 4c 89 c3 4c 89 e9 48 89 d6 e8 2d f0 03 00 4c 8b 6c 24 68 4c 8b bc 24 28 01 00 00 49 89 c0 48 89 cf 48 8b 44 24 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

