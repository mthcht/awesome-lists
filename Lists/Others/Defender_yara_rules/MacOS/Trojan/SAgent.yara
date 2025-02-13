rule Trojan_MacOS_SAgent_A_2147842306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgent.A!MTB"
        threat_id = "2147842306"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db 49 bc c5 4e ec c4 4e ec c4 4e 4c 8d 35 ?? ?? 2c 00 e8 1c 18 00 00 48 63 c8 48 89 c8 49 f7 e4 48 c1 ea 04 48 6b c2 34 48 29 c1 41 8a 04 0e 41 88 04 1f 48 ff c3 49 39 dd 75 d7}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b 57 40 49 8b bf 80 00 00 00 49 8b 4f 60 48 01 d1 48 8b 07 4c 89 f6 4c 8d 85 50 ff ff ff ff 50 28 89 c3 4c 8b a5 50 ff ff ff 49 8b 7f 40 49 8b 4f 78 49 29 fc be 01 00 00 00 4c 89 e2 e8 30 0b 00 00 4c 39 e0 0f 85 ?? ?? ?? ?? 83 fb 01 ?? ?? 83 fb 02 0f 84 ?? ?? ?? ?? 49 8b 7f 78 e8 f2 0a 00 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {41 83 fd 03 0f 84 ?? ?? ?? ?? 41 83 fd 01 0f 87 ?? ?? ?? ?? 4c 8b 65 c0 48 8b 7b 40 48 8b 4b 78 49 29 fc be 01 00 00 00 4c 89 e2 e8 0b 06 00 00 4c 39 e0 0f 85 ?? ?? ?? ?? 41 83 fd 01 ?? ?? 48 8b 55 c8 48 8b 4b 30 48 89 53 28 48 89 4b 38 48 8b bb 80 00 00 00 48 85 ff ?? ?? 4c 8b 4b 40 4c 8b 5b 60 4d 01 cb 4c 8b 17 4c 89 fe 4c 8d 45 c8 48 8d 45 c0 50 41 53 41 ff 52 18 48 83 c4 10 41 89 c5 48 8b 7b 28 48 39 7d c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SAgent_ARM_2147842307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SAgent.ARM!MTB"
        threat_id = "2147842307"
        type = "Trojan"
        platform = "MacOS: "
        family = "SAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 06 00 94 08 7c 40 93 09 7d d6 9b 29 fd 44 d3 28 a1 17 9b 08 6b 68 38 a8 16 00 38 94 06 00 f1 01 ff ff 54}  //weight: 1, accuracy: High
        $x_1_2 = {60 42 40 f9 62 22 40 f9 68 32 40 f9 43 00 08 8b 08 00 40 f9 08 15 40 f9 e4 03 00 91 e1 03 14 aa 00 01 3f d6 f5 03 00 aa e8 03 40 f9 60 22 40 f9 16 01 00 cb 63 3e 40 f9 21 00 80 52 e2 03 16 aa 13 03 00 94 1f 00 16 eb ?? ?? ?? ?? bf 06 00 71}  //weight: 1, accuracy: Low
        $x_1_3 = {88 32 40 f9 a6 00 08 8b 08 00 40 f9 08 0d 40 f9 e4 23 00 91 e7 43 00 91 e1 03 15 aa 00 01 3f d6 f6 03 00 aa e8 07 40 f9 80 16 40 f9 1f 01 00 eb ?? ?? ?? ?? df 0e 00 71 ?? ?? ?? ?? df 06 00 71 ?? ?? ?? ?? e8 0b 40 f9 80 22 40 f9 17 01 00 cb 83 3e 40 f9 21 00 80 52 e2 03 17 aa c4 01 00 94 1f 00 17 eb ?? ?? ?? ?? df 06 00 71 ?? ?? ?? ?? e2 07 40 f9 83 1a 40 f9 82 16 00 f9 83 1e 00 f9 80 42 40 f9 e0 01 00 b4 85 22 40 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

