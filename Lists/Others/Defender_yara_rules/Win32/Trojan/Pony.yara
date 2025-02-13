rule Trojan_Win32_Pony_H_2147730229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.H!MTB"
        threat_id = "2147730229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 80 f2 ?? [0-4] 88 10 [0-4] c3 8b c0 53 51 8b d8 54 6a 40 52 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_I_2147730242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.I!MTB"
        threat_id = "2147730242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 8b c0 53 51 8b d8 54 6a 40 52 53 07 00 8b c0 [0-4] 80 30 ??}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_DA_2147739929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.DA!MTB"
        threat_id = "2147739929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 a1 05 00 00 6a 00 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {10 30 00 10 [0-16] a1 05 00 00 8a ?? ?? (34|80) [0-3] 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_SA_2147742122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.SA!MTB"
        threat_id = "2147742122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ab 44 02 cb 8b fe 1a 65 1b 34 ?? 57 42 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f2 b0 83 4e 44 b2 31 97 f0 08 0e b1 10 00 8b f2 b0 ?? 4e 44 b2 ?? 97 [0-10] f0 08 0e b1 ?? 23 c9 d4 ?? 43 23 57 7c 80 38 ?? 5f 8a 3b 4d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_AZ_2147743681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.AZ!MTB"
        threat_id = "2147743681"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/create /sc MINUTE /tn" ascii //weight: 1
        $x_1_2 = "[InternetShortcut]" ascii //weight: 1
        $x_1_3 = ":Zone.Identifier" ascii //weight: 1
        $x_1_4 = "/C choice /C Y /N /D Y /T 3 & Del \"" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "drivers\\vmhgfs.sys" ascii //weight: 1
        $x_1_7 = "\\drivers\\vmmouse.sys" ascii //weight: 1
        $x_1_8 = "SELECT * FROM Win32_VideoController" ascii //weight: 1
        $x_1_9 = "VirtualBox Graphics Adapter" ascii //weight: 1
        $x_1_10 = "VMware SVGA II" ascii //weight: 1
        $x_1_11 = "TamperProtection" ascii //weight: 1
        $x_1_12 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_13 = "DisableScriptScanning" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_AN_2147837926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.AN!MTB"
        threat_id = "2147837926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {39 c3 ac 25 2d b0 f7 85 6b 6c 6f 67 19 15 8c dd ab 78 fa bf 4f 57 49 52 c1 51 13 44 e4 5a 0b 49 91 53 1b 57 43 87 0a 55 42 ec 33 6f b8 32 25 75 1d 75 01 57 17 5a 08 4d fb bd 13 49 df 9e 05 50 0a 50 0b 51 71}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_AM_2147837928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.AM!MTB"
        threat_id = "2147837928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 f8 26 4f bf 99 fd fd 46 b2 33 c9 2a e0 27 30 4e 3c 56 44 8d 83 3c ec 53 e4 2d 05 0f 5c f3 19 c5 c1 d6 41 b7 c1 11 0a a6 fb f0 7b}  //weight: 1, accuracy: High
        $x_1_2 = {2b 33 71 b5 05 80 c1 82 80 89 9f 4c 8a fd 1e 4b f7 6c 51 10 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_AO_2147837988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.AO!MTB"
        threat_id = "2147837988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 01 1d dc ce 00 8a 89 da fa f1 2b c6 00 88 44 8a 00 3b 00 34 a1 83 bc 46 8b 82 f9 fc 8c 63 63 c5 b1 00 86 00 35 90 89 00 00 34 1b 1d 00 86 3a 00 7e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_AP_2147837995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.AP!MTB"
        threat_id = "2147837995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 01 1b a5 5a 3b 9b 49 ad e0 44 2c 34 91 40 1c 2f 60 11 1d 8e 13 19 51 aa 65 21 4e 03 42 43 f1 b3 89 ec 76}  //weight: 1, accuracy: High
        $x_1_2 = {44 fb fa 14 9f 98 35 94 6f d3 07 ae 96 9e fa 66 42 98 86 37 43 f8 7d 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_AQ_2147841714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.AQ!MTB"
        threat_id = "2147841714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d2 6c 6a 47 52 30 a6 0d 48 b5 c8 86 b2 cf 7c b1 6d 45 b3 bc ed 61 8d e1 c6 86 28 3c 0c 1c f9 86 7b 73 4c 05 3b 4a dc 5e 14 63 fc ef 7e}  //weight: 2, accuracy: High
        $x_2_2 = {21 81 1b 55 ae 4d ef 25 04 5f 0c f5 30 45 96 fb 53 f8 40 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_AR_2147841932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.AR!MTB"
        threat_id = "2147841932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 0c eb ae 3a 8d 2d 25 42 81 ac 69 3f 8f 2d ae cc 29 c4 1a 32 8d 2d f6 b6 08 ed ae 3f 8d c5 1a 3b 8d 2d 27 f7 d4 04 61 bc 64 2f af fe 04 60 ba d7 f2 df 51 c0 eb a6 b2 30 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_AS_2147843812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.AS!MTB"
        threat_id = "2147843812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {34 2d fd 1f 49 00 5f 7d 01 59 a3 94 94 33 e8 ce f3 b2 d1 5b 33 56 4b 3a 16 70}  //weight: 2, accuracy: High
        $x_2_2 = {3d d3 d7 4f 99 bf bc 04 70 54 56 b9 79 0d ac 53 f1 54 1d 58 0b 9e cb 5e 98 24 85 04 70 2a 6b f3 b3 e3 0b 84 7f 5c e3 14 26 4b b6 04 70}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_AT_2147843813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.AT!MTB"
        threat_id = "2147843813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3e 35 72 47 60 a8 98 ff 00 14 e9 39 a3 fc 53 a0 33 a6 32 46 66 ae 98 c9 19 1a 32 32 46 d5 97 41 45 56 00 39 46 99 58 e3}  //weight: 2, accuracy: High
        $x_2_2 = {29 10 8a 44 6a 2d 14 88 45 22 2a d1 44 a1 a2 34 d6 3d 14 44 1f b1 66 5a 80 00 02 b3 10 c4 56 48 4c 62 2a 10 2e 18 08 0e ac 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_RPX_2147847553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.RPX!MTB"
        threat_id = "2147847553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 8b 1c 0e e9 95 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 09 1c 0f 49 49 85 c9 0f 8d 54 ff ff ff 31 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_AU_2147848048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.AU!MTB"
        threat_id = "2147848048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b1 f1 86 16 6a 31 44 33 70 07 91 01 1b b8 9e 3b 75 49 ad fa 88 70 15 d4 40 80 72 60 f8 1d d2 c1 5d 51 98 a9 65 04 03 85 7c}  //weight: 2, accuracy: High
        $x_2_2 = {b4 c4 d9 65 05 b7 97 64 dc 73 a4 05 a2 1c 61 12 aa 2d fd 24 e5 96 84 b1 1f d1 4a 33 ac a0 db 56 de 0a 5c 32 04 7d 37 a7 0f f7 43 dd 96 e5 25 2d b5 21 23 b9 d8 d9 bc 5e 70}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_DAX_2147888522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.DAX!MTB"
        threat_id = "2147888522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1b ae ec ba bb af 69 11 42 32 47 b8 bd 5e ab 9f 44 c1 a3 42 c9 12 b6 73 32 7a 67 a0 82 bc 56 b8 45 3b 61 4b e7 64 95 a8 44 42 a9 4e 1d 77 ff 51 41 be cd 84 09 11}  //weight: 1, accuracy: High
        $x_1_2 = {46 31 5d ca a4 47 29 4a d0 ab 2d 22 49 07 0a d0 cd b8 04 dd b0 6f 87 a9 e9 33 80 e7 67 90 38 43 c8 41 0c 48 90 99 7d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pony_ASC_2147892573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.ASC!MTB"
        threat_id = "2147892573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {97 c9 29 94 e7 ca 43 d0 0e 35 a6 c4 07 ad 41 80 b1 57 b9 4a f8 6e 4f 02 ec c3}  //weight: 1, accuracy: High
        $x_1_2 = {86 24 f3 38 e0 92 30 21 c5 5c 86 03 0a 8b 59 bb 1a 53 19 85 aa 6c 35 6e 1d aa a3 99 d1 25 2a 53 df ed 3a e7 71}  //weight: 1, accuracy: High
        $x_1_3 = {f6 91 be cf 3c 8b 86 64 88 55 15 56 f0 de 94 6c e7 b1 30 47 c4 30 d6 62 0c a4 8a 62 9d}  //weight: 1, accuracy: High
        $x_1_4 = {ba 3c d9 d2 ff c0 e8 2e 92 bc c9 5c 5d e1 35 98 95 6c 8d 15 b4 27 c9 30 d6 05 be bb 6d f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Pony_ASE_2147907256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pony.ASE!MTB"
        threat_id = "2147907256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pony"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ad 30 ca b9 ad 30 ca b9 1d 76 fd 0b 68 8a 37 7e}  //weight: 1, accuracy: High
        $x_1_2 = {0a f1 82 1d 76 fd 0b 6f 88 30 ca 1f 44 fd 01 57 4f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

