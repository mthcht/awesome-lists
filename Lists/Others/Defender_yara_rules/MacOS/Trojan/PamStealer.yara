rule Trojan_MacOS_PamStealer_DA_2147980502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PamStealer.DA!MTB"
        threat_id = "2147980502"
        type = "Trojan"
        platform = "MacOS: "
        family = "PamStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2a 24 b4 e0 8f fb 7e db ad d8 04 65 74 1a 84 94 40 15 4e da 48 0e 6b 0f 78 63 93 4c 45 d5 49 ba 05 73 7e d2 45 f3 f8 70 fa 86 e3 f7 3a 68 88 9c 6e 9d 81 42 96 1b 6e ab 5b df 3f 3f bd ed 2f 7e f9 4b ff 8a 17 e0 14 2b 3f 03 df 1f f9 04 c0 da cb ac 43 d1 f8 a7 89 9e 00 d8 02 ba 89 49 30 e6 92 fb 12 dd 5c 49 fc 87 cf ef 39 b8 f7 f8 c9 27 6e bc 7c e5 b5 33 a7 b7 2f 88 d7 6b 28 36 69 f8 4a 9d e0 b5 e4 b8 6a 12 6f ea a4 8a 2e ea a1 10 f5 d2 ff 49 40 38 21 49 2a 22 b4 24 84 10 87 f1 24 c8 72 92 25 c7 bc 70 42 4b 19 c1 76 08 a0 d9 4a 0a 06 57 6c 26 db 89 13 41 54 60 67 3b a5 fa 51 a1 61 90 af dc f8 a3 19 f8 63 01 14 ce 58 70}  //weight: 10, accuracy: High
        $x_10_2 = {fc fa af eb 76 b6 6f 1b 0e 75 42 9b 34 4d 78 af ee 3e dc a3 bd 80 3a f1 e5 a0 c7 ed e0 39 96 f1 34 64 23 3e 89 15 80 e2 85 1f d3 21 bf e5 3f c7 1d 3f 0e 26 62 4d 02 3a ee 86 8e a3 a1 e4 a6 64 a8 33 cb 06 9a cf 30 f8 e1 5d c7 e1 b6 dc b7 5f e9 15 34 f4 2c f0 3e 9f 7a d1 ca 75 80 4f 37 4d 6b 00 18 d1 5a 36 69 a5 81 51 24 c3 12 b7 c1 15 8c 99 5b b4 34 35 a4 b2 a6 21 c7 b8 f3 71 1e 78 ef 50 21 e0 3d 01 f9 c1 04 e3 78 79 58 43 26 88 92 71 cb 2f 69 89 21 3e 43 56 96 17 0d 36 1a a0 b0 02 c6 83 2d 21 72 b9 db 79 fe f8 b5 3c 82 ee 3e d1 d8 55 cb 35 5c 39 f0 ea}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MacOS_PamStealer_GV_2147980504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/PamStealer.GV!MTB"
        threat_id = "2147980504"
        type = "Trojan"
        platform = "MacOS: "
        family = "PamStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kh-57aebaab0e5de898" ascii //weight: 1
        $x_1_2 = "radr://5614542" ascii //weight: 1
        $x_1_3 = "avenger_agent-" ascii //weight: 1
        $x_1_4 = "/usr/lib/dyld" ascii //weight: 1
        $x_1_5 = "_sqlite3_mutex_alloc" ascii //weight: 1
        $x_1_6 = "_pam_authenticate" ascii //weight: 1
        $x_1_7 = "URLWithString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

