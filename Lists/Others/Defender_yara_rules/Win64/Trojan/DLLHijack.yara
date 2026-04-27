rule Trojan_Win64_DLLHijack_EC_2147923737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.EC!MTB"
        threat_id = "2147923737"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 08 48 8d 40 01 80 c1 4b 80 f1 3f 80 e9 4b 88 48 ff 48 83 ea 01 75 e7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DC_2147933584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DC!MTB"
        threat_id = "2147933584"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "mpclient.dll" ascii //weight: 5
        $x_10_2 = "Hijackdll|Set COM Startup" ascii //weight: 10
        $x_10_3 = "Hijackdll|ReadBuffer" ascii //weight: 10
        $x_1_4 = "Wow64DisableWow64FsRedirection" ascii //weight: 1
        $x_1_5 = "dllhost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DD_2147939089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DD!MTB"
        threat_id = "2147939089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "mpclient.dll" ascii //weight: 5
        $x_10_2 = "C:/ProgramData/PowerToys/" ascii //weight: 10
        $x_10_3 = "d2vtkt11b1a7zs.cloudfront.net" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DE_2147939090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DE!MTB"
        threat_id = "2147939090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /F /IM msedge.exe" ascii //weight: 1
        $x_1_2 = "note.html" ascii //weight: 1
        $x_1_3 = "ransomsvc" ascii //weight: 1
        $x_1_4 = "start-fullscreen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_ARR_2147956040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.ARR!MTB"
        threat_id = "2147956040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {44 8b c0 8b d8 4c 8b 0c 0f 49 8b cd e8 ?? ?? ?? ?? 48 8b c8 48 8d 7f f8 8b 45 f0 33 01 89 5d f0 48 83 ee}  //weight: 8, accuracy: Low
        $x_12_2 = {49 8b cd e8 ?? ?? ?? ?? 48 8b c8 48 8d 7f ?? 8b 45 f0 33 01 89 5d f0 48 83 ee}  //weight: 12, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_ARR_2147956040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.ARR!MTB"
        threat_id = "2147956040"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_25_1 = {48 89 45 f8 48 8b 45 20 48 8b 4d f8 48 89 08 48 8b 45 10 38 00 48 8b 45 10 48 83 c0 ?? 48 8b 4d 10 38 09 48 8b 4d 10 48 83 c1 08 48 2b c1 48 83}  //weight: 25, accuracy: Low
        $x_5_2 = {48 8b 45 20 48 8b 8d 68 ff ff ff 48 89 08 48 8b 45 10 38 00 48 8b 45 10 48 83 c0 48 48 2b 45 10 89 85 44}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DI_2147961773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DI!MTB"
        threat_id = "2147961773"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 63 c2 48 8d 4c 24 20 48 03 c8 0f b6 01 41 88 00 44 88 11 41 0f b6 08 49 03 ca 0f b6 c1 0f b6 4c 04 20 30 0b 48 ff c3 49 83 eb 01 75}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_CH_2147961785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.CH!MTB"
        threat_id = "2147961785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 ca 8a 44 0c 40 88 44 14 40 88 5c 0c 40 0f b6 44 14 40 03 c3 0f b6 c0 8a 54 04 40 41 30 11 49 ff c1 49 83 eb 01 75 a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DL_2147963407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DL!MTB"
        threat_id = "2147963407"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c2 83 e0 0f 42 0f b6 0c 08 48 8d 44 24 [0-4] 48 83 7d 88 10 48 0f 43 44 24 [0-4] f6 d1 30 0c 10 48 ff c2 49 3b d0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DN_2147964497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DN!MTB"
        threat_id = "2147964497"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8d 52 01 48 8b cb 49 0f 45 c9 41 ff c0 0f b6 44 0c [0-1] 4c 8d 49 01 30 42 ff 49 63 c0 48 3b c7 04 00 49 83 f9}  //weight: 10, accuracy: Low
        $x_10_2 = {33 c9 48 8d 52 01 49 83 f9 15 49 0f 45 c9 41 ff c0 0f b6 44 0c [0-1] 4c 8d 49 01 30 42 ff 49 63 c0 48 3b c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_DLLHijack_AKSB_2147965090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.AKSB!MTB"
        threat_id = "2147965090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 3c 06 48 39 cf 74 56 48 83 a5 ?? ?? ?? ?? ?? 48 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 95 ?? ?? ?? ?? 48 89 95 ?? ?? ?? ?? 45 31 c0 45 31 c9 49 83 f9 04 74 18 4e 8b 94 cd ?? ?? ?? ?? 45 8b 1c 0a 46 33 1c 17 45 09 d8 49 ff c1 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_NUK_2147965968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.NUK!MTB"
        threat_id = "2147965968"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4i2XrnKVQy3dn5ZvfZOcW9RHaQE" ascii //weight: 1
        $x_1_2 = "9K8XRsCvR3mb59FV5F4Ygf" ascii //weight: 1
        $x_1_3 = "GWFSo8GYt8xjgqPb29LhQ21yh" ascii //weight: 1
        $x_1_4 = "jM961zeu4EKs8eDo3JnnV2Xg3m5N" ascii //weight: 1
        $x_2_5 = "9XN5Pkfvh23isxmLES4" ascii //weight: 2
        $x_1_6 = "2344uOF5778Ku4lb1b5hZl4mE" ascii //weight: 1
        $x_1_7 = "Encrypted" ascii //weight: 1
        $x_1_8 = "K1Xa6uShOyfaoPF6XD1MSVSt5tU5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DO_2147966831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DO!MTB"
        threat_id = "2147966831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c8 31 d2 49 f7 f1 0f b6 d2 48 89 c1 89 d0 41 f6 f2 0f b6 d4 80 ca 30 0f b6 d2 c1 e2 08 0f b6 c0 01 d0 83 c0 30 66 42 89 44 05 b3}  //weight: 1, accuracy: High
        $n_100_2 = "</CustomerOrderNumber>" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_NVB_2147967591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.NVB!MTB"
        threat_id = "2147967591"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_sqlite_" ascii //weight: 1
        $x_1_2 = {49 c1 c0 28 4d 21 c8 49 09 d0 48 89 f9 4c 31 d1 49 31 ce 48 31 cb 4c 31 c3}  //weight: 1, accuracy: High
        $x_2_3 = {49 89 c2 49 c1 c2 30 49 89 c9 49 c1 c1 30 4c 89 c2 48 c1 c2 30 4d 31 fd 49 31 dc 4c 31 df 49 31 c2 49 31 c9 4c 31 c2 4c 31 eb 48 31 f8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_NVD_2147967835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.NVD!MTB"
        threat_id = "2147967835"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_sqlite_" ascii //weight: 1
        $x_1_2 = {48 8b 85 90 07 00 00 48 33 07 48 8b 8d 98 07 00 00 48 33 4f 08 48 09 c1}  //weight: 1, accuracy: High
        $x_1_3 = {48 d3 e0 48 83 c2 04 48 89 d7 48 89 95 90 16 00 00 49 09 c7 83 c9 20}  //weight: 1, accuracy: High
        $x_2_4 = {4c 39 c1 0f 93 c1 4d 89 cb 49 f7 db 49 39 c3 41 0f 92 c3 41 20 cb 41 80 fb 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

