rule Trojan_Win32_IRCbot_RG_2147775376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCbot.RG!MTB"
        threat_id = "2147775376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bb d7 1e 4f 00 89 d0 e8 ?? ?? ?? ?? 81 c0 0f 59 e7 fc 31 1f 09 d0 81 c0 f1 d3 3d 22 47 89 d0 39 f7 75 dd}  //weight: 2, accuracy: Low
        $x_2_2 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 8b 0c 24 83 c4 04 81 c7 ?? ?? ?? ?? e8 ?? ?? ?? ?? 4e 31 08 29 f6 29 f6 81 c7 ?? ?? ?? ?? 40 81 c7 ?? ?? ?? ?? 39 d8 75}  //weight: 2, accuracy: Low
        $x_2_3 = {29 ff 4f e8 ?? ?? ?? ?? 81 c7 f8 6d a5 e0 31 06 21 f9 81 ef 01 00 00 00 81 c6 01 00 00 00 81 ef 01 00 00 00 09 f9 09 cf 39 d6 75}  //weight: 2, accuracy: Low
        $x_2_4 = {29 ce 41 e8 ?? ?? ?? ?? 29 f6 81 ee b2 63 fe 6b 31 3b 81 c1 fd 76 3c 9e 43 68 56 69 63 d3 5e 09 f1 39 c3 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IRCbot_RH_2147775546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCbot.RH!MTB"
        threat_id = "2147775546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bb ec 09 71 00 89 c9 e8 ?? ?? ?? ?? 81 c6 aa d6 39 c6 31 1f 01 f1 29 c9 81 c7 01 00 00 00 29 f6 be c7 ea 7b e9 4e 39 d7 75}  //weight: 2, accuracy: Low
        $x_2_2 = {29 f7 09 f6 09 f6 e8 ?? ?? ?? ?? 01 f7 57 5e 31 03 4e 29 f6 21 fe 43 56 5e 46 01 ff 39 d3 75}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 34 24 83 c4 04 81 c0 59 e8 51 6f 81 e8 01 00 00 00 e8 ?? ?? ?? ?? 29 ff 29 ff bf 0c 21 db f0 31 33 81 ef ba 94 b0 47 43 21 f8 39 cb 75}  //weight: 2, accuracy: Low
        $x_2_4 = {81 c1 3c fe 02 05 e8 ?? ?? ?? ?? 56 5e 81 c6 01 00 00 00 31 07 81 c6 0a 7b 7d b6 47 46 41 68 5a e5 fc 78 5e 39 d7 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IRCbot_RH_2147775546_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCbot.RH!MTB"
        threat_id = "2147775546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ba 14 8a 43 00 21 ff e8 ?? ?? ?? ?? 81 ef cf 4b d1 69 81 ef 01 00 00 00 81 ef f2 d2 ee 1f 31 16 81 c7 d0 06 5e b1 89 fb 46 4f 39 c6 75 d2}  //weight: 2, accuracy: Low
        $x_2_2 = {be ec 09 71 00 81 c0 74 cc d7 b2 e8 ?? ?? ?? ?? 50 5a 31 37 81 e8 f0 a7 61 26 81 e8 a2 19 5d 28 81 c7 01 00 00 00 81 e8 15 85 63 d7 21 c2 b8 e1 b9 5b 11 39 df 75}  //weight: 2, accuracy: Low
        $x_2_3 = {bb ec 09 71 00 81 c6 43 47 95 62 e8 ?? ?? ?? ?? 01 d2 09 f6 81 c2 01 00 00 00 31 19 81 ea 01 c7 c1 a2 42 81 c1 01 00 00 00 21 f6 29 d2 29 d2 39 f9 75}  //weight: 2, accuracy: Low
        $x_2_4 = {bb ec 09 71 00 09 c9 e8 ?? ?? ?? ?? 81 c2 69 3c 85 d7 31 1f 01 d1 68 bb be a9 2c 59 01 d2 81 c7 01 00 00 00 89 d1 09 c9 ba 13 a3 23 1c 39 c7 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IRCbot_AIC_2147936299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCbot.AIC!MTB"
        threat_id = "2147936299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 4b 51 27 df e8 ?? ?? ?? ?? a3 f4 c5 40 00 b8 f4 15 93 b0 e8 ?? ?? ?? ?? a3 f8 c5 40 00 b8 a5 f1 7c 26 e8 ?? ?? ?? ?? a3 fc c5 40 00 b8 76 b8 f3 c1 e8 ?? ?? ?? ?? a3 00 c6 40 00 b8 c0 d5 8e 02 e8 ?? ?? ?? ?? a3 04 c6 40 00 b8 a8 ed f2 ce e8 ?? ?? ?? ?? a3 e4 c5 40 00 b8 4a 76 87 df e8 ?? ?? ?? ?? a3 08 c6 40 00 b8 50 67 a5 f6 e8 ?? ?? ?? ?? a3 0c c6 40 00 b8 99 dc 99 01 e8 ?? ?? ?? ?? a3 10 c6 40 00 b8 02 97 6b 15 e8 ?? ?? ?? ?? a3 14 c6 40 00 b8 be 72 f3 ff e8 ?? ?? ?? ?? a3 18 c6 40 00 b8 eb 89 dd da e8 ?? ?? ?? ?? a3 1c c6 40 00 b8 1c 1c 60 30 e8 ?? ?? ?? ?? a3 b0 c6 40 00 b8 45 bb 58 e0 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {50 6a 00 e8 ?? ?? ?? ?? 85 c0 0f 94 c3 31 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

