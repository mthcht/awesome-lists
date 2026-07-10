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
        $x_12_1 = {0f b6 0a 48 8d 52 ?? 03 c8 69 c1 ?? ?? ?? ?? 8b c8 c1 e9 06 33 c1 49 83 e8}  //weight: 12, accuracy: Low
        $x_8_2 = {8d 0c c0 8b c1 c1 e8 ?? 33 c1 69 c0}  //weight: 8, accuracy: Low
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
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {44 8b c0 8b d8 4c 8b 0c 0f 49 8b cd e8 ?? ?? ?? ?? 48 8b c8 48 8d 7f f8 8b 45 f0 33 01 89 5d f0 48 83 ee}  //weight: 8, accuracy: Low
        $x_12_2 = {49 8b cd e8 ?? ?? ?? ?? 48 8b c8 48 8d 7f ?? 8b 45 f0 33 01 89 5d f0 48 83 ee}  //weight: 12, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_ARR_2147956040_2
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

rule Trojan_Win64_DLLHijack_NWA_2147969420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.NWA!MTB"
        threat_id = "2147969420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 ff c8 48 d1 c0 49 89 c1 4d 31 c1 48 01 d0 48 d1 c0 49 89 c2 4d 31 c2 4d 01 ca}  //weight: 2, accuracy: High
        $x_1_2 = {41 81 f6 22 40 c0 ca 41 83 c6 1f 41 c1 c6 15 48 ff c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_NWD_2147969421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.NWD!MTB"
        threat_id = "2147969421"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 88 44 04 20 88 4c 14 20 02 4c 04 20 0f b6 c1 44 32 64 04 20 4c 3b 36}  //weight: 2, accuracy: High
        $x_1_2 = {81 74 24 2c 67 68 69 6a c7 44 24 30 61 6d 44 61 81 74 24 34 6f 70 71 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DS_2147972427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DS!MTB"
        threat_id = "2147972427"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {37 00 73 65 61 31 30 35 00 66 6f 72 74 75 6e 65 35 36 00 70 61 6c 65 00 66 72 6f 6d 00 6c 65 74 31 30 36 00 69 74 37 35 00 74 72 75 65 37 37 00 74 68 79 31 32 38 00 69 74 73 00 69 6e 32 34 00 68 75 73 68 39 34 00 66 72 6f 6d 00 6c 65 74 31 30 36 00 6b 65 65 70 73 35 31 00}  //weight: 10, accuracy: High
        $x_10_2 = {6f 70 65 39 38 37 34 00 66 72 6f 6d 39 38 37 35 00 65 6d 62 65 72 73 39 38 37 36 00 6f 66 39 38 37 37 00 64 61 79 39 38 37 38 00 75 6e 66 75 72 6c 39 38 37 39 00 74 68 79 39 38 38 30 00 77 69 6e 67 39 38 38 31 00 74 69 72 65 64 39 38 38 32 00 68 65 61}  //weight: 10, accuracy: High
        $x_10_3 = {69 65 66 73 31 38 31 00 63 61 6c 6d 65 72 31 38 32 00 74 69 64 65 73 31 38 33 00 61 62 69 64 65 31 38 34 00 67 65 6e 74 6c 65 31 38 35 00 68 75 73 68 31 38 36 00 74 68 61 74 31 38 37 00 77 72 61 70 73 31 38 38 00 74 68 65 31 38 39 00 6d 69 64 6e 69 67}  //weight: 10, accuracy: High
        $x_10_4 = {68 00 73 70 69 72 69 74 36 32 00 73 70 69 72 69 74 00 63 6f 64 65 38 30 00 6c 61 79 38 37 00 66 6f 72 00 61 69 72 37 00 61 69 72 37 00 77 68 65 72 65 38 00 67 72 69 65 66 73 38 39 00 6d 69 64 6e 69 67 68 74 36 00 63 68 61 69 72 00 73 6f 72 72 6f 77 31 36 00 66 6f 72}  //weight: 10, accuracy: High
        $x_10_5 = {63 69 38 35 36 31 00 66 61 75 63 69 62 75 73 31 31 30 39 38 00 6f 72 63 69 38 35 36 31 00 6f 72 63 69 38 35 36 31 00 6e 69 62 68 32 38 35 30 00 66 61 75 63 69 62 75 73 31 31 30 39 38 00 6e 69 62 68 32 38 35 30 00 6e 69 62 68 32 38 35 30 00 65 78 32 30 36 30 33 00 6c 6f 72 65 6d 35 39 30 35 00 68 61 62}  //weight: 10, accuracy: High
        $x_10_6 = {75 65 31 37 37 37 39 00 72 69 73 75 73 32 31 31 36 00 64 61 70 69 62 75 73 37 38 39 33 00 6e 61 6d 36 36 30 38 00 69 64 35 30 35 38 00 71 75 69 73 37 37 33 34 00 64 75 69 73 38 38 37 00 72 69}  //weight: 10, accuracy: High
        $x_10_7 = {76 65 73 74 69 62 75 6c 75 6d 32 30 38 33 33 00 61 64 69 70 69 73 63 69 6e 67}  //weight: 10, accuracy: High
        $x_10_8 = {6e 73 65 71 75 61 74 31 39 36 39 31 00 64 61 70 69 62 75 73 31 34 33 37 33 00}  //weight: 10, accuracy: High
        $x_10_9 = {6d 61 6c 65 73 75 61 64 61 31 35 35 39 36 00 63 6f 6e 75 62 69 61 31 35 30}  //weight: 10, accuracy: High
        $x_10_10 = {77 61 6c 6b 32 30 31 39 39 00 74 65 6d 70 65 73 74 31 32 38 34 33 00 74 65 6d 70 65 73 74 39 33}  //weight: 10, accuracy: High
        $x_10_11 = {67 65 6e 74 6c 65 31 00 68 75 73 68 32 00 74 68 61 74 33 00 77 72 61 70 73 34 00 74 68 65 35 00 6d 69 64 6e 69 67}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_DLLHijack_PAA_2147972437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.PAA!MTB"
        threat_id = "2147972437"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 81 ec 98 09 00 00 48 8d ac 24 80 00 00 00 48 8d 4d c0 ba 00 02 00 00 e8 fa 05 00 00 48 85 c0 0f 84 3f 01 00 00 48 89 d6 48 81 fa f7 01 00 00 0f 87 2f 01 00 00 4c 8d 04 36 48 8d bd c0 03 00 00 48 89 f9 48 89 c2}  //weight: 3, accuracy: High
        $x_2_2 = "data.bin" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_GPKE_2147972483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.GPKE!MTB"
        threat_id = "2147972483"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {76 2d d7 7b 32 4c b9 28 32 4c b9 28 32 4c b9 28 3b 34 2a 28 3e 4c b9 28 27 33 bd 29 3a 4c b9 28 27 33 ba 29 36 4c b9 28 27 33 bc 29 2c 4c b9 28}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_MCX_2147972812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.MCX!MTB"
        threat_id = "2147972812"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 69 62 68 35 75 69 63 65 66 2e 64 6c 6c 00 68 35 75 69 5f 63 65 66 5f 61 70 69 5f 68 61 73 68 00 68 35 75 69 5f 63 65 66 5f 62 61 73 65 36 34 65 6e 63 6f 64 65 00 68 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_DV_2147973249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DV!MTB"
        threat_id = "2147973249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e4 84 dc 83 a0 e5 7a 84 dc 83 a0 e6 84 dc 83 a0 e8 84 dc 83 a0 55 e9 84 dc 83 a0 ea 84 dc 83 a0 eb 84 dc 0c 83 a0 ed 84 dc 83 a0 ee 84 dc 83 a0 ef 7a 84 dc 83 a0 f1 84 dc 83 a0 f5 84 dc 83 a0}  //weight: 1, accuracy: High
        $x_1_2 = {a2 af eb 2a ac 9d 4f be e0 9e 70 bf 9e a4 64 60 a0 f2 4c 8a a1 a2 cf b8 81 d6 2a 13 c3 d7 e7 2a a5 1b 1f cc 8f d1 e0 fd 62 58 a6 aa 91 aa 4f a4 2f d8 e4 cf df 29 98 a7 2a a4 24 8f a2 24 5f 1e}  //weight: 1, accuracy: High
        $x_1_3 = {8d 1d c2 80 ff ff 74 34 c6 03 0d eb 2c c6 03 0d 4c 8d 1d b1 80 ff ff eb 20 4f 8b 84 fb 00 de 01 00 4b 8d 14 f6 41 8a 44 d0 38 a8 40 75 09 0c 02 41 88 44 d0 38 eb 05 88 0b 49 03 dd 2b df 75 07}  //weight: 1, accuracy: High
        $x_1_4 = {78 00 74 62 4c 8d 1d 16 81 ff ff 4b 8b 84 fb 00 de 01 00 f6 44 f0 38 48 74 1f 8a 4c 24 70 80 f9 0a 75 05 c6 03 0a eb 6a c6 03 0d 4b 8b 84 fb 00 de 01 00 88 4c f0 3a eb 59 80 7c 24 70 0a 75 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_DLLHijack_DW_2147973250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.DW!MTB"
        threat_id = "2147973250"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd /c sc create MixedSvc binPath= \"C:\\Program Files\\Windows Media Player\\Mixed Reality.exe\" start= auto displayname= \"Windows Mixed Reality Service\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_DLLHijack_AGXB_2147973268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DLLHijack.AGXB!MTB"
        threat_id = "2147973268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 8d 0c 11 0f b6 c9 0f b6 84 0c ?? ?? ?? ?? 41 01 c0 45 0f b6 d8 42 0f b6 bc 1c ?? ?? ?? ?? 40 88 bc 0c ?? ?? ?? ?? 42 88 84 1c ?? ?? ?? ?? 02 84 0c ?? ?? ?? ?? 0f b6 c0 0f b6 84 04 ?? ?? ?? ?? 30 02 48 83 c2 01 49 39 d2 75 b4}  //weight: 5, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "powershell.exe -w hidden -nop -c" ascii //weight: 1
        $x_1_4 = "Get-Partition -DriveLetter" ascii //weight: 1
        $x_1_5 = "(Get-DiskImage -DevicePath $" ascii //weight: 1
        $x_1_6 = ".DriveLetter -eq" ascii //weight: 1
        $x_1_7 = ".InvokeVerb(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

