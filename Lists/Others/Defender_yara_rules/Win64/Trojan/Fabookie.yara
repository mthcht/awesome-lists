rule Trojan_Win64_Fabookie_WY_2147795123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.WY!MTB"
        threat_id = "2147795123"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SendingGh8eu4i proxyPj9k4eh credentialsMn7j4e" wide //weight: 1
        $x_1_2 = "SendingGfe5g requestRgreh4e" wide //weight: 1
        $x_1_3 = "407_khfa4i TheGhehg4g proxyIje4hg requiresDge4gj89 authenticationQerhj4gh" wide //weight: 1
        $x_1_4 = "BreakHghel3g forPe4jjhg multipleTje7i4hg 407_uh7a4r responseP5orjteg" wide //weight: 1
        $x_1_5 = "ProxyBhg4eg isOj4eh: " wide //weight: 1
        $x_1_6 = "named_proxy_policyUh4e8ghggs" wide //weight: 1
        $x_1_7 = "auto_config_url_policyV7he344g7" wide //weight: 1
        $x_1_8 = "auto_detect_policyTe3h7fs4gr" wide //weight: 1
        $x_1_9 = "http://ip-api.com/json" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_MA_2147838926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.MA!MTB"
        threat_id = "2147838926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {e9 97 2a 56 b9 0a d6 1c 1e 25 ae 57 de 0a 52 77 fc 40 b3 44 ec 09 38 79 ae 1b 8a 29 d4 5b bc 3f}  //weight: 2, accuracy: High
        $x_2_2 = {0a 3d af 24 3b 70 81 4b df 5e a1 4d 65 18 45 4a 66 6a 01 74 9a 07 fc 19 6d 13 90 6b 3d 1f 0b 52}  //weight: 2, accuracy: High
        $x_2_3 = {84 11 2e 6d 3f 1c b3 6f 76 62 42 07 dc 41 8d 71 d8 37 26 79 eb 10 84 76 0e 20 67 2a 20 26 34 44}  //weight: 2, accuracy: High
        $x_1_4 = ".vmp1" ascii //weight: 1
        $x_1_5 = "SetThreadAffinityMask" ascii //weight: 1
        $x_1_6 = "WinHttpSetOption" ascii //weight: 1
        $x_1_7 = "GetUserObjectInformationW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_CRQ_2147842948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.CRQ!MTB"
        threat_id = "2147842948"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 d0 4c 63 c0 4e 0f b6 04 01 41 80 f0 ?? 44 88 44 14 [0-5] 83 c0 01 83 f8 ?? 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_SP_2147846620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.SP!MTB"
        threat_id = "2147846620"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 0f b6 01 48 83 c1 01 48 33 d2 4c 0f b6 c0 41 83 e8 01 89 d0 41 3b c0 7f 13 41 83 c0 01 48 63 d0 80 04 11 01 83 c0 01 41 3b c0 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_EM_2147847302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.EM!MTB"
        threat_id = "2147847302"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {48 63 d0 48 83 ec 06 48 8d 64 24 06 80 04 11 08 66 ff f1 48 83 ec 10 48 8d 64 24 02 48 8d 64 24 10 83 c0 01 41 3b c0 e8 00 00 00 00 44 89 74 24 02}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_GJS_2147848817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.GJS!MTB"
        threat_id = "2147848817"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 4c 24 58 48 8d 88 ?? ?? ?? ?? 48 89 4c 24 38 48 8d 80 ?? ?? ?? ?? 48 89 44 24 48 48 8d 78 28 48 8d 47 0e 48 8d 48 0e 48 89 8c 24 a0 00 00 00 48 8d 49 08 48 89 8c 24 ?? ?? ?? ?? 48 8d 49 0f 48 89 4c 24 40 48 8d 49 0a 48 89 4c 24 78 48 8d 49 12 48 89 4c 24 70 48 8d 49 12 48 89 4c 24 68 4c 8d 69 15 49 8d 75 0d 48 89 c1 48 8b 44 24 38}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_EN_2147849124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.EN!MTB"
        threat_id = "2147849124"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 0f b6 01 80 c0 0c 48 83 c1 01 48 33 d2 4c 0f b6 c0 41 83 e8 01 89 d0 41 3b c0 7f 13 41 83 c0 01 48 63 d0 80 04 11 0b 83 c0 01 41 3b c0 75 f1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_DAC_2147849135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.DAC!MTB"
        threat_id = "2147849135"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ff d0 49 89 c5 4c 89 e9 48 89 f2 41 c7 c0 80 84 1e 00 4c 8d 8c 24 bc 00 00 00 48 8b 84 24 98 00 00 00 ff d0 81 bc 24 bc 00 00 00 2c 9e 15 00 73 0f 48 89 f9 ff d3 4c 89 e9 ff d3 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_CRTE_2147849425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.CRTE!MTB"
        threat_id = "2147849425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 40 ff 05 80 00 05 48 8d 40 02 48 83 e9 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_GKH_2147849571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.GKH!MTB"
        threat_id = "2147849571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b ec 48 83 ec ?? c7 45 ?? 48 8b c4 48 c7 45 ?? 89 58 08 4c c7 45 ?? 89 40 18 48 c7 45 ?? 89 50 10 55 c7 45 ?? 56 57 48 83 66 c7 45 ?? ec 30}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_SPS_2147850794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.SPS!MTB"
        threat_id = "2147850794"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 45 e0 41 b9 16 00 00 00 48 2b c8 4c 8d 45 e0 4e 8d 1c 11 43 8a 0c 03 41 ff c9 41 8a 00 49 ff c0 3a c8 75 0d 45 85 c9 75 ea 48 63 c2 49 03 c2 eb 12 ff c2 48 63 ca 48 81 f9 00 e0 0e 00 72 bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_NFB_2147853428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.NFB!MTB"
        threat_id = "2147853428"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 48 03 cf 48 8d 55 e0 41 b8 ?? ?? ?? ?? e8 ea 28 00 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 ?? ?? ?? ?? 72 dc 48 8b 45 ?? eb 06}  //weight: 5, accuracy: Low
        $x_1_2 = "Fbad allocation" ascii //weight: 1
        $x_1_3 = "PatBlt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_RPZ_2147889445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.RPZ!MTB"
        threat_id = "2147889445"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 00 09 eb 19 8b 73 30 49 8b e3 41 5d 41 5c 5f c3 cc cc cc cc cc cc 48 8b c4 48 89 58 08 48 ff c0 48 83 e9 01 75 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_SE_2147890015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.SE!MTB"
        threat_id = "2147890015"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 48 8d 4d 10 41 b8 e8 03 00 00 48 89 4c 24 20 48 8b d3 48 83 c9 ff ff d0 48 8b c3 b9 3c 03 00 00 80 00 08 48 ff c0 48 83 e9 01 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_RPY_2147891410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.RPY!MTB"
        threat_id = "2147891410"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b f0 8b 08 83 e1 3f 80 f9 09 0f 85 6e 01 00 00 48 8d 48 08 48 85 c9 0f 84 7f 01 00 00 80 39 01 0f 85 76 01 00 00 0f b6 69 09 0f b6 41 0a 80 00 0d 48 ff c0 eb 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_RPY_2147891410_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.RPY!MTB"
        threat_id = "2147891410"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 9d 60 01 00 00 43 0f b6 3c 13 49 8b c4 49 f7 e1 48 c1 ea 03 48 8d 04 52 48 c1 e0 02 49 8b c9 48 2b c8 42 0f be 04 29 44 03 c0 44 03 c7 41 81 e0 ff 00 00 80 7d 0d 41 ff c8 41 81 c8 00 ff ff ff 41 ff c0 49 63 c8 42 0f b6 04 19 43 88 04 13 42 88 3c 19 49 ff c1 49 ff c2 48 83 ee 01 75 9f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_NFR_2147898633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.NFR!MTB"
        threat_id = "2147898633"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 e0 48 8b c4 48 eb 23 05 ?? ?? ?? ?? 48 33 c4 48 89 84 24 ?? ?? ?? ?? 48 8b e9 45 33 e4 48 8d 44 24 20 be ?? ?? ?? ?? 4c 8b cd c7 45 e4 89 58 08 4c}  //weight: 5, accuracy: Low
        $x_5_2 = {e9 8e 01 00 00 48 8d 4c 24 ?? ff 15 91 98 ff ff 48 8d 4c 24 20 ff 15 7e 98 ff ff 41 3b c4 75 38 48 8b 0d 8a 2f 03 00 c7 45 ec 89 50 10 55}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_NF_2147898665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.NF!MTB"
        threat_id = "2147898665"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 03 cf 48 8d 55 e0 41 b8 ?? ?? ?? ?? e8 a4 0a 00 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 ?? ?? ?? ?? 72 dc 48 8b 45 10 eb 06 48 63 c3}  //weight: 5, accuracy: Low
        $x_1_2 = "J0sxJ8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_NF_2147898665_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.NF!MTB"
        threat_id = "2147898665"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 03 01 00 00 33 db eb 2b 44 8b 48 ?? 33 c0 8d 58 ?? 84 c9 75 22 46 3b 8c 00 ?? ?? ?? ?? 75 0a 42 8b}  //weight: 5, accuracy: Low
        $x_5_2 = {eb 3b 33 c0 48 8b cf 41 8d 51 ?? e8 6e 2b 00 00 4c 8b 1f 48 8d 54 24 ?? 48 8b cf 41}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_NFA_2147900520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.NFA!MTB"
        threat_id = "2147900520"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 48 03 cf 48 8d 55 e0 41 b8 ?? ?? ?? ?? e8 3f a2 01 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 ?? ?? ?? ?? 72 dc 48 8b 45 10}  //weight: 5, accuracy: Low
        $x_5_2 = {33 d2 83 7b 30 ?? 75 19 39 53 3c 74 14 48 8d 1d 66 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_SPD_2147901102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.SPD!MTB"
        threat_id = "2147901102"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 03 cf 48 8d 55 e0 41 b8 16 00 00 00 e8 7c 12 00 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_KAA_2147901162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.KAA!MTB"
        threat_id = "2147901162"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 03 cf 48 8d 55 ?? 41 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74 14 ff c3 48 63 cb 48 81 f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Fabookie_AH_2147902655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Fabookie.AH!MTB"
        threat_id = "2147902655"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Fabookie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 48 ff c0 48 83 e9 01 75 ba}  //weight: 1, accuracy: High
        $x_1_2 = {80 00 1a eb 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

