rule Trojan_Win32_IRCBot_RTU_2147776817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.RTU!MTB"
        threat_id = "2147776817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be ec 09 71 00 29 db e8 ?? ?? ?? ?? 81 ea 01 00 00 00 4a 09 d3 31 37 81 eb a0 3c a3 7b 81 c7 01 00 00 00 21 d3 39 cf 75}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 ec 09 71 00 09 f7 01 f7 e8 ?? ?? ?? ?? 4e 81 c6 f8 d6 97 9c 89 fe 31 0a 09 f7 47 42 46 29 f7 29 fe 39 c2 75}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 2e ce 43 00 e8 ?? ?? ?? ?? 31 0b 81 c6 01 00 00 00 81 c3 01 00 00 00 89 f6 09 c0 39 d3 75}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ef f0 e1 f4 4b bf 29 1c 4a 58 e8 ?? ?? ?? ?? 21 f8 29 ff 31 11 01 c7 09 ff 41 83 ec 04 89 04 24 58 bf 4e 7e d4 fc 39 f1 75}  //weight: 1, accuracy: Low
        $x_1_5 = {83 ec 04 c7 04 24 2e ce 43 00 8b 0c 24 83 c4 04 21 f7 e8 ?? ?? ?? ?? 31 0a 46 4f 42 bf 03 d1 e2 c6 29 fe 39 da 75}  //weight: 1, accuracy: Low
        $x_1_6 = {83 ec 04 c7 04 24 2e ce 43 00 8b 0c 24 83 c4 04 e8 ?? ?? ?? ?? be 9a cd 63 f4 31 08 40 46 81 ee 7b 8a 00 9d 39 d8 75}  //weight: 1, accuracy: Low
        $x_1_7 = {ba da cc 43 00 89 f6 e8 ?? ?? ?? ?? 89 ff 01 fe 31 13 21 f7 43 39 cb 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IRCBot_RM_2147776912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.RM!MTB"
        threat_id = "2147776912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 10 14 40 00 c3 39 ff 74 ?? ea 31 07 4b 4b 81 c7 04 00 00 00 39 d7 75 ?? 68 b1 b6 30 22 8b 34 24 83 c4 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IRCBot_RT_2147777318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.RT!MTB"
        threat_id = "2147777318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 ec 09 71 00 8b 04 24 83 c4 04 01 f6 89 f1 01 ce e8 1e 00 00 00 81 ee 14 66 46 34 31 02 29 ce 21 f6 01 f6}  //weight: 1, accuracy: High
        $x_1_2 = {68 ec 09 71 00 58 81 ea 15 9b 40 ff 21 db e8 28 00 00 00 21 db 31 06 09 d3 81 c6 01 00 00 00 89 d3 89 d3 21 d3 39 fe 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IRCBot_RT_2147777318_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.RT!MTB"
        threat_id = "2147777318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 13 5d 5b 45 09 c9 e8 ?? ?? ?? ?? 29 db 43 b9 65 5b 3f 9c 31 10 21 cb 81 e9 c0 50 6b a8 41 81 c0 02 00 00 00 b9 65 1e 88 e2 39 f0 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c2 04 4e df 72 e8 ?? ?? ?? ?? 29 d2 31 1f 81 e8 2d 95 16 35 09 d2 01 d0 81 c7 02 00 00 00 89 c2 81 e8 37 95 a6 ef 39 cf 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {81 eb 78 a9 ba c6 e8 ?? ?? ?? ?? 4a 31 07 81 ea 98 d7 0c f8 21 d3 09 d2 81 c7 02 00 00 00 89 da 39 cf 7c}  //weight: 1, accuracy: Low
        $x_1_4 = {bf cc 46 47 00 48 e8 ?? ?? ?? ?? b8 83 5e ce f9 01 db 31 39 29 d8 21 c3 81 c1 02 00 00 00 09 c3 39 f1 7c}  //weight: 1, accuracy: Low
        $x_1_5 = {81 c0 78 16 2b 7c e8 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 31 17 89 d8 21 c0 29 db 81 c7 02 00 00 00 81 c0 37 be 54 81 68 d7 19 e4 24 58 39 cf 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IRCBot_RT_2147777318_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.RT!MTB"
        threat_id = "2147777318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb da cc 43 00 e8 ?? ?? ?? ?? 89 c8 31 1e 81 e9 44 5d ee 23 40 46 39 d6 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bb 2e ce 43 00 56 5a e8 ?? ?? ?? ?? 29 d6 31 1f 09 f6 42 47 68 3b 11 ed 46 5a 81 ee e2 d9 f4 49 39 cf 75}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 2e ce 43 00 81 c7 bf c1 f4 cf e8 ?? ?? ?? ?? 81 ea 01 00 00 00 31 08 4f 40 47 39 f0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {bf 2e ce 43 00 21 f1 e8 ?? ?? ?? ?? 29 ce 31 3b 83 ec 04 89 34 24 8b 34 24 83 c4 04 43 01 f6 81 ee 0e 4f b1 9a 39 c3 75}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 2e ce 43 00 81 ef 91 ae b6 24 01 fb e8 ?? ?? ?? ?? 09 db 81 c7 01 00 00 00 31 01 81 c1 01 00 00 00 47 81 c7 01 00 00 00 39 d1 75}  //weight: 1, accuracy: Low
        $x_1_6 = {be 2e ce 43 00 e8 ?? ?? ?? ?? b8 c7 48 8f db 31 31 41 39 f9 75}  //weight: 1, accuracy: Low
        $x_1_7 = {68 2e ce 43 00 59 e8 ?? ?? ?? ?? 01 fb 29 df 31 0a 89 db 89 df 42 39 c2 75 e6}  //weight: 1, accuracy: Low
        $x_1_8 = {b8 ec 09 71 00 81 c6 07 34 70 c6 e8 ?? ?? ?? ?? 01 f2 31 07 46 be ea d4 4a 61 47 4e 39 df 75}  //weight: 1, accuracy: Low
        $x_1_9 = {ba ec 09 71 00 81 c1 57 a3 16 93 29 ff e8 ?? ?? ?? ?? 01 f9 b9 f6 f9 5d 49 31 16 29 cf 81 c6 01 00 00 00 81 c7 43 37 47 17 01 ff 39 c6 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IRCBot_GKM_2147777847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.GKM!MTB"
        threat_id = "2147777847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5e 01 cf e8 ?? ?? ?? ?? b9 4b c6 13 ec 31 32 81 ef a3 38 7a 37 41 83 ec 04 89 0c 24 8b 0c 24 83 c4 04 81 c2 01 00 00 00 21 cf 01 c9 39 da 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IRCBot_RTH_2147777887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.RTH!MTB"
        threat_id = "2147777887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 ec 09 71 00 5e 4f e8 ?? ?? ?? ?? 29 df 4b 21 df 31 30 09 fb bf df 93 9e 8c 81 c0 01 00 00 00 29 fb 83 ec 04 89 3c 24 5f 81 c3 74 c0 53 5c 39 c8 75}  //weight: 2, accuracy: Low
        $x_2_2 = {bf 2e ce 43 00 21 c0 e8 ?? ?? ?? ?? 09 c3 b8 c4 9c da 43 31 3e 81 e8 50 cd 61 97 29 db 81 c6 01 00 00 00 39 ce 75}  //weight: 2, accuracy: Low
        $x_2_3 = {68 2e ce 43 00 5b 21 f1 e8 ?? ?? ?? ?? 01 f1 31 1a 89 ce 29 f6 42 39 fa 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IRCBot_RTH_2147777887_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.RTH!MTB"
        threat_id = "2147777887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 29 c1 21 c0 e8 ?? ?? ?? ?? 40 31 1e 29 c1 46 68 bd 85 49 2a 59 29 c1 39 fe 75}  //weight: 1, accuracy: Low
        $x_1_2 = {be 6f 48 4f 00 21 d7 21 ff 29 d2 e8 ?? ?? ?? ?? 29 ff 31 31 83 ec 04 89 14 24 5a 89 ff 81 ef 01 00 00 00 81 c1 01 00 00 00 42 39 c1 75}  //weight: 1, accuracy: Low
        $x_1_3 = {5e 01 c0 e8 ?? ?? ?? ?? 49 81 c0 01 00 00 00 31 33 01 c8 81 c0 13 e4 c1 1b 43 09 c1 81 c1 1b 60 54 2c 39 fb 75}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ee 7c 9a fa cf e8 ?? ?? ?? ?? 81 ee 48 d7 01 a4 09 f0 81 c0 19 5f 25 e5 31 1f 01 f6 21 f6 68 b6 ca b8 7b 5e 81 c7 01 00 00 00 21 f6 29 f0 4e 39 d7 75}  //weight: 1, accuracy: Low
        $x_1_5 = {be 6f 48 4f 00 29 cb e8 ?? ?? ?? ?? 81 c3 d9 02 5d dc 81 c1 f5 66 ab b6 31 37 49 49 81 c7 01 00 00 00 21 d9 b9 11 c1 aa 1d 39 c7 75}  //weight: 1, accuracy: Low
        $x_1_6 = {09 d7 09 ff 21 d2 21 d7 42 31 0b f7 d2 81 c2 01 00 00 00 81 c3 02 00 00 00 4f bf 9f f7 75 93 09 d7 39 f3 0f}  //weight: 1, accuracy: High
        $x_1_7 = {09 d7 09 ff 21 d2 21 d7 42 31 0b f7 d2 81 c2 01 00 00 00 81 c3 02 00 00 00 4f bf 9f f7 75 93 09 d7 39 f3 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IRCBot_MR_2147777889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.MR!MTB"
        threat_id = "2147777889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 21 fb 40 [0-2] 81 [0-5] 21 ?? 39 ?? b9 [0-4] 81 [0-5] 09 ?? e8 [0-4] 81 [0-5] 29 ?? 01 ?? 31 ?? bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IRCBot_MS_2147777890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.MS!MTB"
        threat_id = "2147777890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 01 8b [0-2] 8d [0-2] 89 ?? 8b [0-2] 8a [0-3] 30 ?? 8d [0-2] 89 ?? 81 [0-5] 39 ?? 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IRCBot_RW_2147781401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.RW!MTB"
        threat_id = "2147781401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e9 7c 9b f5 d2 e8 ?? ?? ?? ?? 09 c9 40 31 1f 41 81 e9 8d b9 a6 f5 47 b9 9d 57 57 3d 40 39 d7 75}  //weight: 1, accuracy: Low
        $x_1_2 = {bf ce 17 4b 8b e8 ?? ?? ?? ?? 49 b9 17 fb 59 81 51 59 31 16 29 ff 83 ec 04 c7 04 24 1a a7 75 97 8b 0c 24 83}  //weight: 1, accuracy: Low
        $x_1_3 = {43 29 d3 e8 ?? ?? ?? ?? 81 c2 ce 71 a1 f8 01 d2 31 07 42 09 d2 47 29 db 81 ea 12 5c 29 ed 4b 39}  //weight: 1, accuracy: Low
        $x_1_4 = {81 ee ee f2 15 a4 49 e8 ?? ?? ?? ?? 89 ce 31 17 81 e9 44 91 f5 86 09 f6 81 c7 01 00 00 00 81 ee 1a e6 06 04 39}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 7b c6 09 39 09 c1 e8 ?? ?? ?? ?? 29 c0 49 31 3a 01 c0 81 c1 36 31 84 12 42 89 c1 81 c1 fc 97 57 43 39}  //weight: 1, accuracy: Low
        $x_1_6 = {81 ea bb a5 4e ca 81 c0 01 00 00 00 01 c0 e8 ?? ?? ?? ?? 81 ea 52 ff 19 14 09 c0 81 ea 1a e3 77 33 31 31 09 c2 42 41}  //weight: 1, accuracy: Low
        $x_1_7 = {81 c7 8d cd 17 18 89 f6 89 f6 e8 ?? ?? ?? ?? 56 5f 09 f6 4e 31 0a 68 ?? ?? ?? ?? 5e 4f 81 ee f0 e7 e7 f1}  //weight: 1, accuracy: Low
        $x_1_8 = {b8 ca 9f 4c 00 01 f6 e8 ?? ?? ?? ?? 89 ce 31 02 81 ee ?? ?? ?? ?? 42 21 ce 29 ce 39 da 75}  //weight: 1, accuracy: Low
        $x_1_9 = {09 f6 46 46 e8 ?? ?? ?? ?? 21 f2 42 21 d2 31 38 81 c2 ?? ?? ?? ?? 40 42 81 ea ?? ?? ?? ?? 42 39 d8}  //weight: 1, accuracy: Low
        $x_1_10 = {ba 64 8b 5d 00 29 ff 4f e8 ?? ?? ?? ?? 81 c1 6f 15 f2 a3 89 cf 31 13 09 cf 09 c9 81 c3 02}  //weight: 1, accuracy: Low
        $x_1_11 = {81 e8 d6 45 1e 3c e8 ?? ?? ?? ?? 4e 21 c0 81 e8 01 00 00 00 31 11 83 ec 04 c7 04 24 76 d9 9b 98 8b 04 24 83 c4 04}  //weight: 1, accuracy: Low
        $x_1_12 = {4a 89 d6 e8 ?? ?? ?? ?? 81 c6 01 00 00 00 81 c2 80 0f 3e 56 81 c6 24 cd 37 5c 31 3b 21 f6 46 89 d6}  //weight: 1, accuracy: Low
        $x_1_13 = {bf 2d c9 4e 00 29 c2 e8 ?? ?? ?? ?? 81 c0 51 99 d1 f6 31 3e 48 81 c6 01 00 00 00 81 c2 01 00 00 00 40 ba 21 4e e4 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IRCBot_MA_2147838929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.MA!MTB"
        threat_id = "2147838929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c3 03 c0 03 46 24 33 d2 52 50 a1 ?? ?? ?? ?? 99 03 04 24 13 54 24 04 83 c4 08 66 8b 00 66 25 ff ff 0f b7 c0 c1 e0 02 03 46 1c 33 d2 52 50 a1 ?? ?? ?? ?? 99 03 04 24 13 54 24 04 83 c4 08 8b 00 03 05 ?? ?? ?? ?? 89 45 f8 43 83 7d f8 00 75 ?? 3b 5e 18 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IRCBot_EN_2147850146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.EN!MTB"
        threat_id = "2147850146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyDoom Infectat" ascii //weight: 1
        $x_1_2 = "netbios_infected" ascii //weight: 1
        $x_1_3 = "fuck21" ascii //weight: 1
        $x_1_4 = "Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_1_5 = "us.undernet.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IRCBot_EM_2147850147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.EM!MTB"
        threat_id = "2147850147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 3e 21 c9 81 c3 01 00 00 00 81 c6 01 00 00 00 39 c6 75 e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IRCBot_EC_2147850525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.EC!MTB"
        threat_id = "2147850525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 08 03 45 fc 0f b6 10 33 14 8d ?? ?? ?? ?? 8b 45 08 03 45 fc 88 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IRCBot_DS_2147852319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.DS!MTB"
        threat_id = "2147852319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac 53 56 57 33 c9 89 4d ac 89 4d b0 89 4d b8 89 4d b4 89 4d bc 89 4d ec 89 55 f8 89 45 fc 8b 45 f8 e8 99 a5 ff ff 33 c0 55 68 09 9f 40 00 64 ff 30 64 89 20 33 c0 89 45 f4 8b 45 fc ff 70 14 68 24 9f 40}  //weight: 1, accuracy: High
        $x_1_2 = {33 c0 89 45 d0 8b 45 f8 e8 67 a5 ff ff 89 45 d4 33 c0 89 45 dc 8b 45 ec e8 57 a3 ff ff 50 8b 45 ec e8 4e a5 ff ff 50 6a 00 e8 ba ae ff ff 50 e8 ac ae ff ff e8 0b fd ff ff 85 c0 74 0c 66 b8 03 00 66 c7 45 f2 03}  //weight: 1, accuracy: High
        $x_1_3 = {83 c4 f0 8b d8 33 ed 33 ff 8d 43 10 e8 7b 9b ff ff 83 fd 01 1b c0 40 3c 01 75 4a 8b 43 10 ba d8 a3 40 00 e8 28 9f ff ff 75 0a 8d 43 10 e8 5a 9b ff ff eb 39 8b 43 10 ba e4 a3 40 00 e8 0f 9f ff ff 75 0d 8d 43 10 ba d8 a3 40}  //weight: 1, accuracy: High
        $x_1_4 = {a1 70 b1 40 00 ff 00 66 c7 04 24 02 00 68 bd 01 00 00 e8 6e a9 ff ff 66 89 44 24 02 8b 43 10 e8 19 9f ff ff 50 e8 63 a9 ff ff 89 44 24 04 6a 10 8d 44 24 04 50 56 e8 42 a9}  //weight: 1, accuracy: High
        $x_1_5 = {68 d7 75 00 00 e8 2b a9 ff ff 66 89 44 24 02 8b 43 10 e8 d6 9e ff ff 50 e8 20 a9 ff ff 89 44 24 04 6a 10 8d 44 24 04 50 56 e8 ff a8 ff ff 40 74 05 83 cf ff eb 07 a1 70 b1 40 00 ff 00 85 ff 74 1f 56 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IRCBot_MK_2147957104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IRCBot.MK!MTB"
        threat_id = "2147957104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IRCBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {21 0f 2b 42 ?? ef 4f 21 32 38 ?? ?? ?? ?? ?? 48 6b 2b 14}  //weight: 15, accuracy: Low
        $x_10_2 = {8b 5f 04 8d 84 30 98 af 0a 00 01 f3 50 83 c7 08 ff 96 ?? ?? ?? ?? 95 8a 07 47 08 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

