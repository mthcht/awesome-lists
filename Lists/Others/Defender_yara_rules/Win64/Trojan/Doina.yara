rule Trojan_Win64_Doina_ND_2147900480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.ND!MTB"
        threat_id = "2147900480"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {78 0f 3b 35 60 af 02 00 73 07 b8 ?? ?? ?? ?? eb 02 33 c0 85 c0 75 33 41 c6 41 38 ?? 41 83 61 34}  //weight: 5, accuracy: Low
        $x_1_2 = "DeleteFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Doina_CCHI_2147902002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.CCHI!MTB"
        threat_id = "2147902002"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/output" ascii //weight: 1
        $x_1_2 = "/Login Data" ascii //weight: 1
        $x_1_3 = "/History" ascii //weight: 1
        $x_1_4 = "/Web Data" ascii //weight: 1
        $x_1_5 = "/network/cookies" ascii //weight: 1
        $x_1_6 = "/logindata" ascii //weight: 1
        $x_1_7 = "/webdata" ascii //weight: 1
        $x_1_8 = "/cookie" ascii //weight: 1
        $x_1_9 = "/session" ascii //weight: 1
        $x_1_10 = "/log" ascii //weight: 1
        $x_1_11 = "/autofill" ascii //weight: 1
        $x_1_12 = "chat_id" ascii //weight: 1
        $x_1_13 = "/sendDocument" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Doina_CH_2147903155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.CH!MTB"
        threat_id = "2147903155"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Users\\Public\\winRes\\qr.bmp" wide //weight: 2
        $x_1_2 = "185.216.68.72" wide //weight: 1
        $x_1_3 = "185.246.90.200" wide //weight: 1
        $x_1_4 = "files/test.exe" wide //weight: 1
        $x_1_5 = "Public\\Videos\\winRes\\aaa.exe" wide //weight: 1
        $x_1_6 = "YOU HAVE BEEN BETRAYED!" wide //weight: 1
        $x_1_7 = "your criminal activities are linked to your real identity!" wide //weight: 1
        $x_1_8 = "Thats why we have compromised your device and" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Doina_A_2147918464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.A!MTB"
        threat_id = "2147918464"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {15 82 95 d2 02 74 24 58 8b c3 aa 19 4f f5 26 b5 19 a0 0f f1 0d 6e 9d f3 0d c8 15 f0 0d c9 f0 0d ca b0 0b cb 55 c6 54 40 cc b0 0a cd 70 0e ce 70 0c cf 55 70 0e d0 30 09 d1 b0 0c d2 f0 09 d3 55 30 01 d4 70 0e d5 b0 02 d6 b0 00 d7 55 70 01 d8 30 00 d9 30 02 da 70 0b db 55 b0 03 dc 70 0e dd b0 00 de f0 02 df 55}  //weight: 1, accuracy: High
        $x_1_2 = {40 9c 55 00 e5 9d c0 02 9e 80 76 9f 80 72 a0 05 60 02 a1 00 6f a2 6f c6 40 a3 00 67 c6 40 a4 49 c6 40 a5 00 6e c6 40 a6 64 c6 40 a7 15 e0 03 a8 60 07 a9 e0 05 aa 63 c6 04 40 ab 60 07 ac 50 c6 40 ad 15 60 06 ae e0 02 af e0 00 b0 6d c6 00 40 b1 57 44 88 60 b2 c6 00 40 88 75 c6 40 89 73 c6 54 40 8a e0 05 8b e0 03 8c 80 79 8d 00 32 c6 40 8e 2e c6 40 8f 25 e0 09 90 e0 0c 91 6c 60 05 92 ff 88 15 11 41 61 65 54 24 40 a2 5f 0a 1b a0 01 41 c0 62 64 44 89 a4 04 24 b8 e0 17 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Doina_ALP_2147921729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.ALP!MTB"
        threat_id = "2147921729"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 03 c2 33 c8 8d 04 32 33 c8 44 2b e9 41 8b cd 41 8b c5 c1 e9 05 c1 e0 04 41 03 c9 41 03 c7 33 c8 42 8d 04 2a 81 c2 47 86 c8 61 33 c8 2b f1 41 ff c8 75 bf}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Doina_SPDG_2147935586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.SPDG!MTB"
        threat_id = "2147935586"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "http://113.105.224.81:8088/google.htm" ascii //weight: 3
        $x_1_2 = {63 6d 64 20 2f 63 20 74 61 73 6b 6c 69 73 74 ?? 64 61 74 61 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_2_3 = "wireshark" ascii //weight: 2
        $x_1_4 = "GameTroyHorseDetect" ascii //weight: 1
        $x_2_5 = "WinNetCap" ascii //weight: 2
        $x_2_6 = "SpyNet" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Doina_ARA_2147949562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.ARA!MTB"
        threat_id = "2147949562"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 09 33 c8 8b c1 48 8b 4c 24 38 48 8b 94 24 60 01 00 00 48 03 d1 48 8b ca 88 01 e9 1a ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Doina_MCG_2147951785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Doina.MCG!MTB"
        threat_id = "2147951785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 73 64 67 6e 72 74 72 74 67 00 63 76 62 63 76 62 00 64 66 67 64 65 79 65 72 74 79 00 68 6a 6b 74 79 6a 66 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

