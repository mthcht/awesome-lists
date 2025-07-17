rule Trojan_Win32_Neoreblamy_AC_2147812835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AC!MTB"
        threat_id = "2147812835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f4 0f b6 84 05 45 ff ff ff 8b 4d f4 2b 4d d0 0f b6 8c 0d 42 ff ff ff 0f be 8c 0d b8 fe ff ff 0b c1 8b 4d f4 0f b6 8c 0d 45 ff ff ff 8b 55 f4 2b 55 d0 0f b6 94 15 42 ff ff ff 0f be 94 15 b8 fe ff ff 23 ca 2b c1 8b 4d f4 0f b6 8c 0d 44 ff ff ff 88 84 0d b8 fe ff ff 83 65 d0 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_AC_2147812835_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AC!MTB"
        threat_id = "2147812835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b fe 8b 74 24 1c 8b cb d3 ff 8b c7 8d 4c 24 20 33 c6 99 52 50}  //weight: 2, accuracy: High
        $x_2_2 = {55 8b ec 83 e4 f8 83 ec 1c 53 c7 44 24 04 ?? ?? 00 00 81 7c 24 04 ?? ?? 00 00 56 57}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_AD_2147812836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AD!MTB"
        threat_id = "2147812836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {23 ca 2b c1 8b 4d ?? 0f b6 4c 0d ?? 8b 55 ?? 2b 55 ?? 0f b6 54 15 ?? 0f b7 54 55 ?? 23 ca 2b c1 8b 4d ?? 0f b6 4c 0d ?? 66 89 44 4d}  //weight: 10, accuracy: Low
        $x_3_2 = "FreeLibraryWhenCallbackReturns" ascii //weight: 3
        $x_3_3 = "GetLogicalProcessorInformation" ascii //weight: 3
        $x_3_4 = "SetThreadStackGuarantee" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_K_2147812837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.K!MTB"
        threat_id = "2147812837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 40 c1 e0 00 0f b6 44 05 ?? 83 c8 ?? 33 c9 41 c1 e1 00 0f b6 4c 0d ?? 83 e1 ?? 2b c1 33 c9 41 6b c9 00 0f b6 4c 0d ?? 66 89 44 4d}  //weight: 1, accuracy: Low
        $x_1_2 = "I become the guy" ascii //weight: 1
        $x_1_3 = "Oh, my keyboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_KZ_2147812838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.KZ!MTB"
        threat_id = "2147812838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OMG>.< I don't know!" ascii //weight: 1
        $x_1_2 = "ml. from cup #" ascii //weight: 1
        $x_1_3 = "fxotybyjkcgdtrtmootmfcwkogtivemkvoiulgkjkswecddhirekd" ascii //weight: 1
        $x_1_4 = "trhwhsllljbdrmkekvmqbcmutqhxgwwfrsaucbntctmqhlrybnrh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_KY_2147812839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.KY!MTB"
        threat_id = "2147812839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FORTRAN 77" ascii //weight: 1
        $x_1_2 = "ml. from cup #" ascii //weight: 1
        $x_1_3 = "FastestFinger" ascii //weight: 1
        $x_1_4 = "mgigqmstjshwnblvvvwyqmlgrmhlijadrwppnaeinmgonkgucnyogqyl" ascii //weight: 1
        $x_1_5 = {89 cb c1 e3 03 09 d3 00 dc be ?? ?? ?? ?? 66 ad 31 db 89 cb c1 e3 03 09 d3 00 dc be ?? ?? ?? ?? 66 ad 00 d4 b8 ff ff ff ff be ?? ?? ?? ?? 66 ad 00 d4 b8 ff ff ff ff be ?? ?? ?? ?? 66 ad 31 db 89 cb c1 e3 03 09 d3 00 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CL_2147812840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CL!MTB"
        threat_id = "2147812840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {2b c8 2b ca 03 4d e4 89 4d e4}  //weight: 3, accuracy: High
        $x_2_2 = {ff ff 59 59 8b 4d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CL_2147812840_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CL!MTB"
        threat_id = "2147812840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 0a 33 c6 69 f0 93 01 00 01 42 83 fa 04 72 ee}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 8b c6 6a 0e 59 f7 f1 8b 45 08 8b 0c b3 8b 14 90 8b c1 23 c2 03 c0 2b c8 03 ca 89 0c b3 46 3b f7 72 dc}  //weight: 1, accuracy: High
        $x_1_3 = "GetTickCount" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_2147841147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy"
        threat_id = "2147841147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wrutfk" ascii //weight: 1
        $x_1_2 = "nylqeso" ascii //weight: 1
        $x_1_3 = "lopnbd" ascii //weight: 1
        $x_1_4 = "gitgahc" ascii //weight: 1
        $x_2_5 = "ShowOwnedPopups" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_EM_2147847197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.EM!MTB"
        threat_id = "2147847197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {59 59 8b 4d f8 8b 09 03 c1 99 b9 07 ca 9a 3b f7 f9 8b 45 f8 89 10}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_EM_2147847197_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.EM!MTB"
        threat_id = "2147847197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {89 45 fc 8b 45 fc 89 45 f8 8b 45 f8 8b 4d f8 8b 00 23 41 04 83 f8 ff 74 0a 8b 4d fc 8b 01 8b 51 04 eb 59 8b 45 fc 83 20 00 83 60 04 00 ff 75 0c 8b 45 0c 8b 4d 08}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GJH_2147847355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GJH!MTB"
        threat_id = "2147847355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yqbvvlm scctuimh ybqhox jabt fhjpomxk rch yjje qekd hbwfc ineyy" ascii //weight: 1
        $x_1_2 = "aovbc emu tps cldr tmphbxc" ascii //weight: 1
        $x_1_3 = "xbisv dlrblpomi crvnqqnxy hpj" ascii //weight: 1
        $x_1_4 = "choej abjdn xnp obqjsq ypd bmihjxgxv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GMH_2147888911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GMH!MTB"
        threat_id = "2147888911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cf 8a 1c 01 8d 50 56 8a cb e8 ?? ?? ?? ?? 0f be f0 33 d2 0f be c3 03 45 fc 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc 39 47 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GMH_2147888911_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GMH!MTB"
        threat_id = "2147888911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 ec 40 89 45 ec 83 7d ec 03 ?? ?? 6a 01 8d 45 f8 50 6a 01 68 68 35 00 00 6a 00 68 32 2c 00 00 68 b9 38 00 00 e8 ?? ?? ?? ?? 83 c4 1c}  //weight: 10, accuracy: Low
        $x_1_2 = "XEzOZDUTXftEUBHjV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_A_2147906217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.A!MTB"
        threat_id = "2147906217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 07 8b 48 04 8a 44 39 40 8b 4c 39 38 88 45}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4d e8 8b 45 ?? 89 1c 88 ff 45 e8 39 75 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {8b c7 8d 4d ?? 33 c6 99 52 50 e8 ?? ?? ?? ?? 59 59 83 78}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_B_2147906310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.B!MTB"
        threat_id = "2147906310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e0 33 45 ?? 99 89 45}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 06 85 c0 0f 99 c2 8b 0f 8b 06 2b ca 33 d2 3b c8 8b 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_C_2147906314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.C!MTB"
        threat_id = "2147906314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff ff 99 f7 bd ac ?? ff ff 03 95 24 ?? ff ff 03 95 e0 ?? ff ff 8b c2 99 89 85 30}  //weight: 2, accuracy: Low
        $x_2_2 = {d3 e0 0b 85 fc ?? ff ff 99 89 85 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_D_2147907100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.D!MTB"
        threat_id = "2147907100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 59 89 06 89 46 ?? 8d 04 98 89 46 ?? 89 7d fc 8b 0e 8b c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_E_2147907200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.E!MTB"
        threat_id = "2147907200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 40 89 45 fc 83 7d fc 02 7d ?? 8b 45 fc c7 84 85 88}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_EC_2147908398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.EC!MTB"
        threat_id = "2147908398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 d2 8b c6 6a 34 59 f7 f1 8b 45 08 8b 0c b3 8b 14 90 8b c1 23 c2 03 c0 2b c8 03 ca 89 0c b3 46 3b f7 72 dc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_EC_2147908398_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.EC!MTB"
        threat_id = "2147908398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 14 01 8d 48 11 8a c1 22 c2 02 c0 2a c8 0f be c2 03 45 fc 02 ca 0f be f1 33 d2 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RM_2147908627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RM!MTB"
        threat_id = "2147908627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 08 8d 45 d4 89 5d fc 56 6a 00 68 8c 2b 00 00 68 a7 00 00 00 50 ba 12 0c 00 00 b9 8d 6b 00 00 e8}  //weight: 1, accuracy: High
        $x_1_2 = {49 49 23 c8 74 ?? 33 c0 40 8b ?? ?? ?? ?? ?? d3 e0 8b ?? ?? ?? ?? ?? 2b c8 89 0e 00 d3 e0 8b ?? ?? ?? ?? ?? 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Neoreblamy_RM_2147908627_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RM!MTB"
        threat_id = "2147908627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 58 d1 e0 8b 84 05 ?? ?? ff ff 48 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0 83 bc 05 ?? ?? ff ff 00 7c 72}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 14 ff 75 08 68 99 27 00 00 68 2c 0d 00 00 ff 75 0c 6a 00 68 67 11 00 00 68 20 64 00 00 ff 75 10 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RN_2147909394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RN!MTB"
        threat_id = "2147909394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 51 68 cf 00 00 00 68 24 32 00 00 51 52 51 51 68 ec 48 00 00 ff 75 0c 8d 55 fc b9 e7 1c 00 00 ff 75 08 e8 0a 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RP_2147909710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RP!MTB"
        threat_id = "2147909710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 2a c8 0f be c2 03 45 fc 02 ca 0f be f1 33 d2 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RS_2147909835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RS!MTB"
        threat_id = "2147909835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 45 f8 ff 31 8b 45 fc 83 c0 0c 68 44 b3 06 10 89 45 fc ff 30 6a 03 68 51 03 00 00 56 e8 8d fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RS_2147909835_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RS!MTB"
        threat_id = "2147909835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be f0 33 d2 0f be c3 03 45 fc 6a 19 59 f7 f1 8b 45 fc 8b ca d3 e6 8b 4d f8 03 ce 40 89 4d f8 89 45 fc 39 47 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RV_2147910504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RV!MTB"
        threat_id = "2147910504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 75 0c 8b c2 ba 03 0f 00 00 68 7c 4b 00 00 ff 75 10 68 3e 24 00 00 6a 01 51 68 eb 1b 00 00 ff 75 08 8b c8 68 d3 5c 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RA_2147912584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RA!MTB"
        threat_id = "2147912584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4c 24 10 57 8b c2 99 6a 18 5b f7 fb 89 5c 24 24 8b f0 8b 45 08 2b c1 89 74 24 20 99 8b fe f7 fb 89 44 24 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RB_2147912585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RB!MTB"
        threat_id = "2147912585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 4d f8 57 8b c2 99 6a 18 5b f7 fb 89 5d e8 8b f0 8b 45 08 2b c1 89 75 ec 99 8b fe f7 fb 89 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RB_2147912585_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RB!MTB"
        threat_id = "2147912585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d 08 01 75 1c e8 ?? ?? ?? ?? 99 6a 03 59 f7 f9 42 42 69 c2 e8 03 00 00 50 ff 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RR_2147913105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RR!MTB"
        threat_id = "2147913105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 16 59 33 d2 8b c6 f7 f1 8b 45 08 8b 0c b3 8b 14 90 e8 cc ff ff ff 89 04 b3 46 3b f7 72 e1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RC_2147914155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RC!MTB"
        threat_id = "2147914155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b c6 6a ?? 59 f7 f1 8b 45 08 8b 0c b3 8b 14 ?? 8b c1 23 c2 03 c0 2b c8 03 ca 89 0c b3 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RD_2147914332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RD!MTB"
        threat_id = "2147914332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 f8 33 45 dc 99 89 85 58 ff ff ff 89 95 5c ff ff ff ff b5 5c ff ff ff ff b5 58 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RD_2147914332_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RD!MTB"
        threat_id = "2147914332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 8b cf 40 d3 e0 85 c2 0f 95 c2 85 c3 0f 95 c0 8a c8 0a c2 22 ca 0f b6 c0 33 d2 84 c9 0f 45 c2 8b 55 fc 03 f6 0f b6 c8 0b f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RE_2147914503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RE!MTB"
        threat_id = "2147914503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d fc 8b 14 01 83 c2 01 6b 45 f4 74 8b 4d fc 89 14 01 6b 55 f4 74 8b 45 fc 8b 0c 10 83 e9 01 6b 55 f4 74 8b 45 fc 89 4c 10 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ANR_2147915253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ANR!MTB"
        threat_id = "2147915253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 9d c1 81 f9 ed 1a 10 88 1b c9 33 d2 41 3b c1 0f 9f c2 69 45 d4 f9 47 00 00 33 c9 3b d0 0f 9e c1 81 e9 02 fc 00 00 f7 d9 1b c9 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ANE_2147915274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ANE!MTB"
        threat_id = "2147915274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yBIwEaeeOUFbOrfMOaTDGlDoVKox" ascii //weight: 1
        $x_1_2 = "ABSMvNsiwcnhJUvFOnXKIRaJegDnQt" ascii //weight: 1
        $x_1_3 = "xcWkWuCwPYedugCbhGhLaEDWQfjoD" ascii //weight: 1
        $x_1_4 = "wjUgAeICjnTbiETALhEcewWAVCSmE" ascii //weight: 1
        $x_1_5 = "ncCNRLWFNHQnprtku" ascii //weight: 1
        $x_1_6 = "ZpTzcFsEKixxexqjaFPdter" ascii //weight: 1
        $x_1_7 = "SOVeUZBI" ascii //weight: 1
        $x_1_8 = "ptZbHSKnbmPUipEFImG" ascii //weight: 1
        $x_1_9 = "pZiEOznMsTgddhwU" ascii //weight: 1
        $x_1_10 = "tBNyzIIYTDcQRWFVko" ascii //weight: 1
        $x_1_11 = "wwrfstaGXSIxkdfYEJiXATBTI" ascii //weight: 1
        $x_1_12 = "KujrBSOwGDTBEiKBolTPwL" ascii //weight: 1
        $x_1_13 = "wvUAyJADstRsQeDcv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_AO_2147915510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AO!MTB"
        threat_id = "2147915510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdZfAoUwymYcKDyvhWObYsLdWyGPBU" ascii //weight: 1
        $x_1_2 = "cTOZFJHdxLPvueNOjClAQUNpfnnX" ascii //weight: 1
        $x_1_3 = "fOOufmGnqIABQpnYgYPqmOUfOrfQ" ascii //weight: 1
        $x_1_4 = "ueNqDjihFZbmFOGuvlbDfQGbLoWb" ascii //weight: 1
        $x_1_5 = "HwXFfSSyciqwBLjkWOgyXXsbTAaWNY" ascii //weight: 1
        $x_1_6 = "zlXBWEEaHNtxtRiVRNwgNZrnkwZWS" ascii //weight: 1
        $x_1_7 = "zlkVVIEOIbJHVdDepuDDcdQZgGCsc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_RF_2147915940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.RF!MTB"
        threat_id = "2147915940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 f8 00 00 00 68 db 19 00 00 68 fd 2a 00 00 68 09 49 00 00 6a 01 6a 00 ff 75 8c ff 75 88 68 aa 22 00 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_AQ_2147916403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AQ!MTB"
        threat_id = "2147916403"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QqrbfpDhlOMDQIzPxGHEJjOEaEhEa" ascii //weight: 1
        $x_1_2 = "pFUJnCzvLTsCVGkWzZDytUHxXgZdF" ascii //weight: 1
        $x_1_3 = "VfHcZjffZsTPdTWShrXeKheBahHgx" ascii //weight: 1
        $x_1_4 = "nHsjZlpxnSCMsasgVAJto" ascii //weight: 1
        $x_1_5 = "KUtfkWcTyzFQItjiUQIvcT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASA_2147916960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASA!MTB"
        threat_id = "2147916960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BnelqbRvMtoEWPBUbgyubHyBJpJGEB" ascii //weight: 1
        $x_1_2 = "huXkwzeouonixlmWz" ascii //weight: 1
        $x_1_3 = "fwLYDUZUcoYeDFYkBoOVhNomTGOLaPnovN" ascii //weight: 1
        $x_1_4 = "mgnVPcrLihAGzMbVZAmVVBRecVyJ" ascii //weight: 1
        $x_1_5 = "YgymvWYlVhFCkgxqodqHMevBTNOO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASB_2147916961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASB!MTB"
        threat_id = "2147916961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hlfpCkgPKUJwxaArcRynZn" ascii //weight: 1
        $x_1_2 = "ptEHhqDcuaijwKQAeeYgEjZvhvfO" ascii //weight: 1
        $x_1_3 = "vYFKIDBcKbGTUknkkgNQMDqoOupLvo" ascii //weight: 1
        $x_1_4 = "xooBipYNfxLanhGgoHjCRHePLeGYR" ascii //weight: 1
        $x_1_5 = "AVTXRUINmLablxSmabnNsiBjskRCawCBof" ascii //weight: 1
        $x_1_6 = "SSoQHjdPlTKeWUqKgKhhwiE" ascii //weight: 1
        $x_1_7 = "kBwtnkHUtGIjlLdydzwvxuwcMoRDTA" ascii //weight: 1
        $x_1_8 = "WusPebppWWJQogPWyGjlyoAaxpyM" ascii //weight: 1
        $x_1_9 = "gvasaWXLdpADUwuuBfrbsyQvyWVRtX" ascii //weight: 1
        $x_1_10 = "fDuONwLoggshmDuyBScLaOwLyEkT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Neoreblamy_AP_2147917040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AP!MTB"
        threat_id = "2147917040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec ff 75 18 68 1b 03 00 00 6a 01 ff 75 08 68 4c 28 00 00 ff 75 14 68 f2 28 00 00 ff 75 0c 68 e8 4a 00 00 ff 75 10 68 c9 38 00 00 6a 01 e8 ?? ?? 00 00 83 c4 30 5d c3}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 85 7c ff ff ff 10 b9 13 17 c7 85 dc fb ff ff 5c 46 f2 0b c7 85 88 ea ff ff a9 51 03 ec c7 85 08 f4 ff ff 87 59 b0 91}  //weight: 2, accuracy: High
        $x_1_3 = "gbITNPwbYsMlaGlDWnIXgBGgFWsHVtBN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASC_2147917058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASC!MTB"
        threat_id = "2147917058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WdlTxhAtRfKoKSZdNyLmDnBzBelqi" ascii //weight: 1
        $x_1_2 = "DMDqrlyxTQylPBDEgqfAkEEZsdBtz" ascii //weight: 1
        $x_1_3 = "YiTTKEUzdDOLNtOJNHVLeHvmxOrdM" ascii //weight: 1
        $x_1_4 = "GUkKeJPikEzIIvnSHmANHAeju" ascii //weight: 1
        $x_1_5 = "mukxNgRSyQfGtEVAiHZDwZHScVtCoDmkza" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASD_2147917222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASD!MTB"
        threat_id = "2147917222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pCkGCAubNKjddBVItuoYywgzA" ascii //weight: 1
        $x_1_2 = "wiozjQjYSkndZnqvidutACSPzUK" ascii //weight: 1
        $x_1_3 = "usbnHLcPbBIoBznsEdJUQazWKvqmiGOsuMcjUhrae" ascii //weight: 1
        $x_1_4 = "SXLmHPFaEjbmjdnwOUzWCYIdbsXEpi" ascii //weight: 1
        $x_1_5 = "aGFuBOSwoGeuSNlEXcNPVjhnSAf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASE_2147917226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASE!MTB"
        threat_id = "2147917226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IgMBNivjHYupogbdsAMKilNhRwYanhaT" ascii //weight: 1
        $x_1_2 = "gSgQVeRMFFeFgLQNLzGgltmQBLM" ascii //weight: 1
        $x_1_3 = "KBdcsryyIVGUgFnqHoaMkCXrYzDYQnDdJJx" ascii //weight: 1
        $x_1_4 = "aaImRLyonHCpCqUpbkXTPxCvn" ascii //weight: 1
        $x_1_5 = "CiTXfuUZYdbPXmNnaeMDELdajjiM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASF_2147917655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASF!MTB"
        threat_id = "2147917655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EfyexHFAtsJpVktMQEGNVbUbuxUaWP" ascii //weight: 1
        $x_1_2 = "BrRmXFrVhiMBbrDGFIxVCgzkpifA" ascii //weight: 1
        $x_1_3 = "XUofKoXBFJaHTBGlDRwTdCUlKrSCCnHjKA" ascii //weight: 1
        $x_1_4 = "ZtNddFPvPSJBvQtOzXowOTcJiGxeX" ascii //weight: 1
        $x_1_5 = "wmVckGkcwuXuPVtDAZNhkGbRQdgcvJ" ascii //weight: 1
        $x_1_6 = "VYUxvsbfjcwSWkpIQWSoGXffvtHx" ascii //weight: 1
        $x_1_7 = "wiNIHRUBtpkAqQvvDWUsmICWwKzIjB" ascii //weight: 1
        $x_1_8 = "mlwoEKCSShfWjNSJLkbLGRgfBCNT" ascii //weight: 1
        $x_1_9 = "heqUxnuLvDWrMaVLDYaUuoPlazbkGGNSov" ascii //weight: 1
        $x_1_10 = "KJSDFVppHwOJYqMLXupmSMNKwHoXSgPRMa" ascii //weight: 1
        $x_1_11 = "qCYbfFYmGYIsAdzSijUmndDKrvwRpHvFVkf" ascii //weight: 1
        $x_1_12 = "JUsPSmAeeWvGBKyqGYCDUOmexPJLheFB" ascii //weight: 1
        $x_1_13 = "xxuZqXVxcPiLXvMQSqpAHnbcEOHybUrXXrJTTgJjICeoaDxQqtP" ascii //weight: 1
        $x_1_14 = "QnTYNRhBkghuQcMgQeMhccZyLrriYujwztRjQsxUl" ascii //weight: 1
        $x_1_15 = "ygORzCoMvVWORxIVYGTnemSiQQMdhCqaRLobn" ascii //weight: 1
        $x_1_16 = "xzakHXTpeHswQftaFtvwLlFsrgRIapnFO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASG_2147917916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASG!MTB"
        threat_id = "2147917916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wWAXSQVokUkxfzAQGSqXAfxkTMIyyUVF" ascii //weight: 1
        $x_1_2 = "bbOzeddgpxCZdsAviIewTdZhdnfskamHnGNJJecag" ascii //weight: 1
        $x_1_3 = "qaNJTvjPYdEFgUGcVPKBoQlKIwRyZmH" ascii //weight: 1
        $x_1_4 = "aoQTGTqbmXvIuYDlpdIjmhURTYCTGQqQjU" ascii //weight: 1
        $x_1_5 = "yklwZmhLZnxkjHRvUBlQAWwKPgehyi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASI_2147918292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASI!MTB"
        threat_id = "2147918292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XNvNtkzciTWOmggiaBIdDAlceQZ" ascii //weight: 1
        $x_1_2 = "ulMuaKXCZMmFDqzTJixBpSVcyAVtvRrIiwYJWGPhTGftjQLEIYz" ascii //weight: 1
        $x_1_3 = "vnaeifFmfoOoeEmeWtBPoHDDPpZXPFz" ascii //weight: 1
        $x_1_4 = "UeTdQEmCicCDAEKkWdqGLBbTuPzHecJWMxOsS" ascii //weight: 1
        $x_1_5 = "VRVZcpiffsHAnNGQFiJBRLcnaoZwFdCBke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_SPSH_2147918396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.SPSH!MTB"
        threat_id = "2147918396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BjsdKzpmuZzKroK" ascii //weight: 2
        $x_1_2 = "LuFOqzyiXOpePkCtxhekGFCWu" ascii //weight: 1
        $x_1_3 = "VcwcOZFSwoRBZgutnysa" ascii //weight: 1
        $x_1_4 = "JXCLnAPqSOOZqAxQZkpz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPA_2147918504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPA!MTB"
        threat_id = "2147918504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RywjRURvTHxFkk" ascii //weight: 1
        $x_3_2 = "EkDmRTHVLqBoJvetwcsLjMw" ascii //weight: 3
        $x_5_3 = "FgbdIYubCAnaElbGjlq" ascii //weight: 5
        $x_7_4 = "qQptxMomkNymuOqXMrWXba" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPB_2147918595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPB!MTB"
        threat_id = "2147918595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UovlTegQiyFNbzmPA" ascii //weight: 1
        $x_3_2 = "wQMwRbVHfUeLriTfv" ascii //weight: 3
        $x_5_3 = "DfTspRbZGckHHfmYCTasYfc" ascii //weight: 5
        $x_7_4 = "yGFpMKNyfMbkArLapy" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASJ_2147918602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASJ!MTB"
        threat_id = "2147918602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hSzACesAwpbbueBXfUqVGbJ" ascii //weight: 1
        $x_1_2 = "YfWeNVNHffsqLGqsdfrjNSMdYOdxUxRp" ascii //weight: 1
        $x_1_3 = "BaEzsQMEYTCgmHxYMJRcPNowwe" ascii //weight: 1
        $x_1_4 = "yVrCadYijLVpqhasTZnxdkymGYJRq" ascii //weight: 1
        $x_1_5 = "BkBdffuSxHbvJJTmcIUzggrnrequu" ascii //weight: 1
        $x_1_6 = "vaDHEazMJLRAMrLcLtgsUSdjEAe" ascii //weight: 1
        $x_1_7 = "xpwXDpGMLsWYXMxRsNYFCqy" ascii //weight: 1
        $x_1_8 = "RwIatgpQJgAKXrGpcFztVbPwWiiQDNLn" ascii //weight: 1
        $x_1_9 = "qqKwMOvdaLThwsGJclnlQnpCopDPwfANlfJLGSn" ascii //weight: 1
        $x_1_10 = "ElNBADQrwrqICtdMdeOoArACeci" ascii //weight: 1
        $x_1_11 = "nDyCmUzxUXkXeCugZwmndRBFXoOry" ascii //weight: 1
        $x_1_12 = "abKQMgWQvJYTQqtGNzUlrwd" ascii //weight: 1
        $x_1_13 = "CiTXfuUZYdbPXmNnaeMDELdajjiM" ascii //weight: 1
        $x_1_14 = "ZiegyTNCQGjTGtNAcKqIhksvrACORgwhRjhN" ascii //weight: 1
        $x_1_15 = "gySLGMvOMDBCrfnvEeoKpHYxOKwGQDB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASK_2147918708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASK!MTB"
        threat_id = "2147918708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bjJlRrINAtkRxmkveI" ascii //weight: 1
        $x_1_2 = "UCAhtKLUxZoGNNamSqpZeowxCKDOJ" ascii //weight: 1
        $x_1_3 = "dMehrlqREhvaVsLbIoliaeQaVnfuLnXKdkgKG" ascii //weight: 1
        $x_1_4 = "pyywsczsDTsrheFVGysPJjEIEDiUyKFlRvn" ascii //weight: 1
        $x_1_5 = "mzIkskJpvWuBKQbFvfAVBsHLukBinuHuvPIYgnY" ascii //weight: 1
        $x_1_6 = "TyPInlwHIHVXhrsbftaCyKFtXHFaQGkfveRONbNyGT" ascii //weight: 1
        $x_1_7 = "pxmCpAmYbayldEalIIWjTDVCdeXLUtKWnDKOt" ascii //weight: 1
        $x_1_8 = "DnsOtBmBPQOyaeXFNGQbbvGcjsYXVWrWLY" ascii //weight: 1
        $x_1_9 = "NhtwyrpzsInnYqsCMdHYSxWCkznHLl" ascii //weight: 1
        $x_1_10 = "GVYlugxPlVWpFFDDhUqNEpEPJYkYIxpVqY" ascii //weight: 1
        $x_1_11 = "OBnCasvPIwxWLAsmTqOjDRfNoUWehBAbQwHM" ascii //weight: 1
        $x_1_12 = "ePeyqKssuOoXySycqOYbPHEUtOelPaAWvfiniCg" ascii //weight: 1
        $x_1_13 = "aySaNELeREqJUlvwYHKfKrevSYBvwk" ascii //weight: 1
        $x_1_14 = "EOHbhWtjsCFqQHPPVpvXOkbKcykOiX" ascii //weight: 1
        $x_1_15 = "JgaSerfGgYZpJmlcmWcujQXJHWZorxnYsZKyp" ascii //weight: 1
        $x_1_16 = "CxOuzAoSucgGgmbSqwtZjsTtRatboLosXKHDByT" ascii //weight: 1
        $x_1_17 = "GFdpomHQZcPUcXXFBsspLRyOmzgd" ascii //weight: 1
        $x_1_18 = "qtiRKADNrMPrxaYZuQSLahCqgzIliNbXKU" ascii //weight: 1
        $x_1_19 = "tdEnxALSaBBQNKUitmrholsbpzetm" ascii //weight: 1
        $x_1_20 = "JlTgsSsEDMgPixUnbnPzmEvxQOpFS" ascii //weight: 1
        $x_1_21 = "SmaOGoacGjbZLWCnvJYPMOpttZitmj" ascii //weight: 1
        $x_1_22 = "KzLfTlOTgoLMlaIBCHWmdyKymAfAIVmmcy" ascii //weight: 1
        $x_1_23 = "mrbBgThteSVFYRXIQYVkxzjBNPghVEQmIy" ascii //weight: 1
        $x_1_24 = "CieKwQmZzGDPnDIovXzAYrLPalbLQWUlcPty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASL_2147918978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASL!MTB"
        threat_id = "2147918978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jRhkTfgSEqQGqcnMbYHRbyMyMSNKjU" ascii //weight: 1
        $x_1_2 = "UvJcTAgHWCyDqCJtKgiKsaxWgxEgVN" ascii //weight: 1
        $x_1_3 = "ESXQoeXEjSFdZcFHNwNJuFMoWWrxYBXanlsyH" ascii //weight: 1
        $x_1_4 = "qeXYDiNcAXbtiUKnwMbsFDjYWbglUdlXjv" ascii //weight: 1
        $x_1_5 = "SzckAEMmSQwcbgBOMknWXjFVeGeSOXxgku" ascii //weight: 1
        $x_1_6 = "OjrrKlScCkKhJxwTzygzibOPurXmkVwbclLxB" ascii //weight: 1
        $x_1_7 = "chDfqpgmgZrFqTFExXfGtoTtmfmLatIZdaSzcZLsjxxYYNrBXkJ" ascii //weight: 1
        $x_1_8 = "RaGDmEqNXKpoPmxiTPANRlDqt" ascii //weight: 1
        $x_1_9 = "OoeMNmuWPnYUnVlElXgRuaUKcIDhZa" ascii //weight: 1
        $x_1_10 = "HVRVuZSxgGwXJAhleJQlSYbMAcKBtu" ascii //weight: 1
        $x_1_11 = "PTpPKWjlfdDeGpNmTFQCZnoQsdyASgQNmt" ascii //weight: 1
        $x_1_12 = "BCiZXMuPyRnwvEKmjiSyGRnxpkCShIzlQVZuixKDAw" ascii //weight: 1
        $x_1_13 = "MCLwhjlFnNFRtHDaNjTvnGbaoAYa" ascii //weight: 1
        $x_1_14 = "xBzXsMVaqaqMxcjuhCtZMHIwjzuBECWHuV" ascii //weight: 1
        $x_1_15 = "YfsEYMqDjdtjyRAElUAPwpXEjTyKbFq" ascii //weight: 1
        $x_1_16 = "PtQPzdfDgYsquoaUWkHGsguEYTxlLjnkvKmrPGw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASM_2147918992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASM!MTB"
        threat_id = "2147918992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZKldSKBJIGRgTJbbpdWgJqmeEdruoa" ascii //weight: 1
        $x_1_2 = "rsmZaGShKgCJDDiRiwVpxxLTQoRG" ascii //weight: 1
        $x_1_3 = "RTqFpTODZNplMwyuzDYAwHdZhWyBqHLtFB" ascii //weight: 1
        $x_1_4 = "yQEsqaBkvMmFwRdZQzGDVcFAsaJFJSlSiPOIDTwUu" ascii //weight: 1
        $x_1_5 = "OnaXuqSmkpnSXzGdYTXixxNHIdBQwt" ascii //weight: 1
        $x_1_6 = "ZOiIqlVZDQmAteNGrMJKnZYvIMnmZiSUuJ" ascii //weight: 1
        $x_1_7 = "HzxAfUljHQkooUsnfougjjHinVLRZeyEhHfmuJNVoW" ascii //weight: 1
        $x_1_8 = "cDwygoNgSJgpBkklllJyXyzmKHfYkvgPTOvOrskwl" ascii //weight: 1
        $x_1_9 = "FTtJkMMhPFCBZSlsBRklUgMMqoAHbLyqUe" ascii //weight: 1
        $x_1_10 = "QJHuhZGzhDHCuPyBTmWtyvouJodVzmYGMcUJzpovVX" ascii //weight: 1
        $x_1_11 = "rrLlrMMLmFYoTpqlGfMszKjeIuqFojjUxKoemGpOuKiAeVyDFOs" ascii //weight: 1
        $x_1_12 = "CGUYRiRQwnWsNOCdxoTjbVOke" ascii //weight: 1
        $x_1_13 = "thgtLTKrcZueHwrITOIBtHBLIQHrLp" ascii //weight: 1
        $x_1_14 = "LCTOvdkBeRhsElDJRoOCQQdoGMBc" ascii //weight: 1
        $x_1_15 = "jgfhZelmLnaUcGVhyCIoApHYUYOCGZEDieGPjCv" ascii //weight: 1
        $x_1_16 = "kUQwTClIhBAWMhbqkYuiqfXXCuxyKCYLIYHXeUOIT" ascii //weight: 1
        $x_1_17 = "KeMXwtxNEdIdUnsxOoXzjOqLgMWqahseroWcYXROjQwYAfscgDf" ascii //weight: 1
        $x_1_18 = "bPwmTBTnnMTfmkWSERHcRHBSuxqb" ascii //weight: 1
        $x_1_19 = "DiyfhRqaXYLyGuOCQCZffVdNDgvBkqbwiMOSw" ascii //weight: 1
        $x_1_20 = "NFoiuOeHzShSYLfGSzeJXrFBkfhkCqnErpjgJzJBz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASN_2147919078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASN!MTB"
        threat_id = "2147919078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YIgmVIuxQEkNMpeWGSHBiRYHaxqkIj" ascii //weight: 1
        $x_1_2 = "DDntGvAMAXrGKHjwmaJeLteSpWUifn" ascii //weight: 1
        $x_1_3 = "SzdGaitnikRUtDHhbfsqPQDnCBWQpSiZLkKiP" ascii //weight: 1
        $x_1_4 = "kxniPSOrccXdCfTBsAVthdzTMVGFrOSaKYjNnnQ" ascii //weight: 1
        $x_1_5 = "RwFFGEhZuioiaMVqzTxVfZxHgsJYRI" ascii //weight: 1
        $x_1_6 = "rKofcrccUwiKiekrDtqoLAZaIEkZUaTIRP" ascii //weight: 1
        $x_1_7 = "QyQRJCUIkLBVOgdkGsodfkGDgMXqgFqYxdVXw" ascii //weight: 1
        $x_1_8 = "REHxJRuVggpwudhwotmVWHNwKHxJTdKeBY" ascii //weight: 1
        $x_1_9 = "qVTXJdjjboVCulckmeUMRMRmyfTNkh" ascii //weight: 1
        $x_1_10 = "uWhvkYhOOxHtbmPQUfcheEpqAoqB" ascii //weight: 1
        $x_1_11 = "oGMWVffHripxQheexPAhVcWZvrmEduGMJevs" ascii //weight: 1
        $x_1_12 = "BNbeUfNaCOHDAqUvTxrtfKbvXMhESekClnyxWIBHb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASO_2147919710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASO!MTB"
        threat_id = "2147919710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zPMSxSdxMhQYRzzDGTYHGCXeiVBzCi" ascii //weight: 1
        $x_1_2 = "rWzrvQYZWWbnsSzUAlFQjeLIpSCVRGyZjb" ascii //weight: 1
        $x_1_3 = "ZtMgnvwAqYJExMiZFkVdpMSsLdgKqKjbXp" ascii //weight: 1
        $x_1_4 = "AUxAbyoPMdNdaKZZAVivvZATkCTxvyJdrZSqDhnuMn" ascii //weight: 1
        $x_1_5 = "WeCLxQzoxGZHZGVNMncrBWAeKvnjNM" ascii //weight: 1
        $x_1_6 = "wANpwFvqBLdQbHZkOAuiLmXGuqtnvtluLC" ascii //weight: 1
        $x_1_7 = "UOriwOPGiBftlRlKocEqjFrHauAaLlyRRXEh" ascii //weight: 1
        $x_1_8 = "pnIIPOAIFSZSdNHkUretDCqOucMVJdImCsCjZOY" ascii //weight: 1
        $x_1_9 = "zCUrdpyiMNnWZQPkQBsIIZnAGJmWLE" ascii //weight: 1
        $x_1_10 = "MMznjIcSNfVzlZILXwYPhyrkdPRJISoGUZ" ascii //weight: 1
        $x_1_11 = "yijWjhXPOZJFdpZbYcJEcBMSEbqmrbUKKwHiqVZzgu" ascii //weight: 1
        $x_1_12 = "eiegIaJjiQENryrszwsgCmujqRzAWvyeMvV" ascii //weight: 1
        $x_1_13 = "NJEVRWUOKAYRVmLfwFrmsuNmGyiI" ascii //weight: 1
        $x_1_14 = "iRzTEYDEGDlCXixoVRKdTzhQeqvxXSPwxb" ascii //weight: 1
        $x_1_15 = "nxzAqxBAydWjWAXNlDhVpzXVPEcQDJtpjiudtuQztL" ascii //weight: 1
        $x_1_16 = "VtXsscJrLfsBJuohLtAKeEVyUgjGpdIAgD" ascii //weight: 1
        $x_1_17 = "OZSuRpJvOliamVUZqxKTzYDWjhEQAm" ascii //weight: 1
        $x_1_18 = "GOOKjiPwEqpxfswyIGkOdaNWzLTWDoOaUz" ascii //weight: 1
        $x_1_19 = "YoueDBllAEQZCYanrepQoaqDhzFttIoNSGLHq" ascii //weight: 1
        $x_1_20 = "bESGkGqlRQMSTkqHNWLUFtsZvNLYlDZJPUzIZgg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPC_2147919741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPC!MTB"
        threat_id = "2147919741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VrgcifQlZtruzgMnM" ascii //weight: 1
        $x_3_2 = "KjdcbCqcaSTusNSJWecwpJu" ascii //weight: 3
        $x_5_3 = "IWiwjYkoJvQnzeWAz" ascii //weight: 5
        $x_7_4 = "dTiHdTJvPxdLYR" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASP_2147920000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASP!MTB"
        threat_id = "2147920000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ocfUGNaeCiFrsSfMqrTwYwugHygKsM" ascii //weight: 1
        $x_1_2 = "HuhUplMHuyvTPOZokFzTYcSUzSqWQ" ascii //weight: 1
        $x_1_3 = "WxGvokfBFJczLOiYIzaHShTcgXVCkSmeit" ascii //weight: 1
        $x_1_4 = "IbxXaedKzAaePasdxQrpWgfvZUFIcwHRyeudNxr" ascii //weight: 1
        $x_1_5 = "eeZmocAdsGCCRcWzDXKqKEghRHml" ascii //weight: 1
        $x_1_6 = "adkHqKoQeUFITBSEnAcRkfZbmoQbZKsNgO" ascii //weight: 1
        $x_1_7 = "trcnKJjYmHXbbWDpNtufMqTWUmCYLvomsjEt" ascii //weight: 1
        $x_1_8 = "mWaKNPEqWLYRyLDrGdqixHYyKzKahxyhivZwklQZt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_CZ_2147920196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CZ!MTB"
        threat_id = "2147920196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 e0 03 45 f4 c6 00 eb 0f b6 45 ff 48 48 8b 4d e0 03 4d f4 88 41 01 0f b6 45 ff 03 45 f4 89 45 f4 eb}  //weight: 2, accuracy: High
        $x_1_2 = "GPvsPFqwtsMlKOQqZUIYBOtBqwdl" ascii //weight: 1
        $x_1_3 = "SOrGmWZrCZSgmEBXdKNZLEoOwFMU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_BG_2147920597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BG!MTB"
        threat_id = "2147920597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yGggPgNTrmQPzLuMXzKIpgmzwtZLtVYtIL" ascii //weight: 1
        $x_1_2 = "sRdERgnYxbWZcPoUKiiNHxPECYYFc" ascii //weight: 1
        $x_1_3 = "BmjKHsfmNOygCNPKFJVnonpMwSyRpElttxvhnGHQI" ascii //weight: 1
        $x_1_4 = "LUsICGAsgAScYTmjSJRApNmocmLksZbh" ascii //weight: 1
        $x_1_5 = "vxedqDPpCqRUvWSkRKNtOGIUtaOCQmrjGz" ascii //weight: 1
        $x_1_6 = "uEjbMGdofjGDvzxgwjvVfdSTtvGZB" ascii //weight: 1
        $x_1_7 = "wBWKKGKYSnGvwXSQQGEgiNk" ascii //weight: 1
        $x_1_8 = "mwvDOcOUTXrfbMeZCBxXuOJDBcJgwCBVCAVm" ascii //weight: 1
        $x_1_9 = "eDIpMRBZeYmpNRPdcbKaocFmmtktvI" ascii //weight: 1
        $x_1_10 = "OKxRhqpbRNeFACxROwyypgKiNUVKzzsqkg" ascii //weight: 1
        $x_1_11 = "AViSRSIvGFsyPxJROkfiDqb" ascii //weight: 1
        $x_1_12 = "PhtoEyzgYCJHPQDlLfoSACrTCPx" ascii //weight: 1
        $x_1_13 = "kDeQdPCKVQtXDkdwJcHotJBMIaCZzM" ascii //weight: 1
        $x_1_14 = "WriNfHHKLJWPmngvmhQeVjHQwbos" ascii //weight: 1
        $x_1_15 = "AqpKmJPAeoTLMMpbQzwNQItCOGzdXCpENP" ascii //weight: 1
        $x_1_16 = "GaMkAXlBApuPPXjVCUeUmebzsscvFsmbkc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASQ_2147921654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASQ!MTB"
        threat_id = "2147921654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dqVISnqSpPrYCQEBUwMmCdmyDQYXEt" ascii //weight: 1
        $x_1_2 = "AsspQwpfLaemUWBPYMpvNXsNunlDFA" ascii //weight: 1
        $x_1_3 = "AguFwjhgOuoeLNskmOhIFsByVdxXDgvdiG" ascii //weight: 1
        $x_1_4 = "qqoJuCdamRIPwHUT.dll" ascii //weight: 1
        $x_1_5 = "sgbmAUQgWfeqQdRbWRuFLlrmb" ascii //weight: 1
        $x_1_6 = "ijXDCRihturDIvzKtCwDTuoumUkhVi" ascii //weight: 1
        $x_1_7 = "IkKoNKXebVusyzOktwyfsSYlvOzXihkxGO" ascii //weight: 1
        $x_1_8 = "mqhcjkHfvTpkwQQvsIzffFJPmgGIGucMsGhqfJacVmiRjhrEjbL" ascii //weight: 1
        $x_1_9 = "GdpUExbNERXzZQBJWCMosfmeGInkaK" ascii //weight: 1
        $x_1_10 = "KhxAwwAXLfaulAkmimggHYJZQULDeWyChE" ascii //weight: 1
        $x_1_11 = "qsinHoekOaBVXkEwbWcaroPTSJpvD" ascii //weight: 1
        $x_1_12 = "uGtxnRqAZWtofhxBiCwzXGNsSnZJsSyo" ascii //weight: 1
        $x_1_13 = "wfIozXWgHTUzNcnkpklfTbkxdhgbgU" ascii //weight: 1
        $x_1_14 = "qQWNJaVmfwVFZWutqsMwPGvtUkyf" ascii //weight: 1
        $x_1_15 = "OmtqQTRsSRNxdUZeKMduKXImSzCMcjDmrf" ascii //weight: 1
        $x_1_16 = "WcgVCQGuFUy.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASR_2147921656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASR!MTB"
        threat_id = "2147921656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fnWgrHpUOKSPNfRmqNmvtpIZpZOeVIjHaM" ascii //weight: 1
        $x_1_2 = "FhsjawEjwUHblyZTtoVEGjNKpdmcSb" ascii //weight: 1
        $x_1_3 = "hLowcrqMkGJBcftWGyPAyJMZyaQgGcPQgl" ascii //weight: 1
        $x_1_4 = "ALofRioPzJWVIAmiSEWNnrgObJpdIK" ascii //weight: 1
        $x_1_5 = "tkHhGIsAgPFjdRhvMWrKWUVPcOgtDm" ascii //weight: 1
        $x_1_6 = "ARUgqdRXrdMpZkIzvRPUimEKsuBD" ascii //weight: 1
        $x_1_7 = "cEtsVFmswEpBJJzunScRDSVtzHICONXtmA" ascii //weight: 1
        $x_1_8 = "atDrQchkcxiWaaPZQhhxvWSXWfXlMSvXJJhiq" ascii //weight: 1
        $x_1_9 = "SMNdFoXoRiKXKtvMSdPyHQzEqrsFQp" ascii //weight: 1
        $x_1_10 = "RbQdEZctJSbTLppuBcWsIhEVQmddTUzHKu" ascii //weight: 1
        $x_1_11 = "BsdmaJBzuWDgCqZzdxWujAFWluynJ" ascii //weight: 1
        $x_1_12 = "vIbHXabjQgmwoHPibMwJVCDyaSMLhuHYXmTR" ascii //weight: 1
        $x_1_13 = "lVvnXqVUDgAbYYHGxjpvNlKjhTVYrv" ascii //weight: 1
        $x_1_14 = "lxKvGwMnZtGDUMThpxPxfdCOOcdZHjNyyc" ascii //weight: 1
        $x_1_15 = "qjFtWCPlFEMUJAwxRjVBvlgBTJWnL" ascii //weight: 1
        $x_1_16 = "HnGVdPUFoXGgjBQFjTreNaYSsgiOwEp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_AST_2147921659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.AST!MTB"
        threat_id = "2147921659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "erOgVBBSwRwVvpSdroEqiffCJEEwRpRoMR" ascii //weight: 1
        $x_1_2 = "SvwPNnGdvHMApnsTeLtjJfNyKdSdIR" ascii //weight: 1
        $x_1_3 = "DVWepnVJZHIFihGOHnnqWLQPBGpoIoYQmlRKJ" ascii //weight: 1
        $x_1_4 = "wflnlRWjUZFRElxCAbZTxkybqfsrCnQfopJKgpdzusyyrFiyXoJ" ascii //weight: 1
        $x_1_5 = "cyecZHCwjDxXsFzOKmeELwBFsQFYeR" ascii //weight: 1
        $x_1_6 = "xYWaDeSyCMKMLRXshPuolKrPyPkeRgGflq" ascii //weight: 1
        $x_1_7 = "aEayDJbzbLvzHXXGFkeEpFgGBcFjt" ascii //weight: 1
        $x_1_8 = "cVwNUrcQzuOxNfkmXVbIUgfCBveBaikMQErsWpDsu" ascii //weight: 1
        $x_1_9 = "ROlLSvSjysRcYvjXMflrNRxTkAqdEZ" ascii //weight: 1
        $x_1_10 = "zRERNEZEgOfQEaPxOdOvnkMEgygw" ascii //weight: 1
        $x_1_11 = "mIewqrCpeZLGMWfMdGZaUtxOHzYI" ascii //weight: 1
        $x_1_12 = "TAxchAwhXckDSovdmgchsOWZZDdbq" ascii //weight: 1
        $x_1_13 = "oMRJlUCQDbHJKCQeunAbOwnhggZp" ascii //weight: 1
        $x_1_14 = "rhIZFUrMtaBlSydyYkDANTYjmRzNeaAoXa" ascii //weight: 1
        $x_1_15 = "EuYRIrNhjiVFVzJTbLepAyyhXxZjFduXmmA" ascii //weight: 1
        $x_1_16 = "rCRuPtKuJcsexDrHkrEdLzbMEWIFStlqAKnRagEAA" ascii //weight: 1
        $x_1_17 = "jeyArBfMBhWFsAwgkSbqCtlYLUZvHW" ascii //weight: 1
        $x_1_18 = "YvJbNxyevgULAeLwMVEXqcoVpUseDfEvrV" ascii //weight: 1
        $x_1_19 = "rMgdZrQYVUKmsDNZwPjFyVxkPNAWB" ascii //weight: 1
        $x_1_20 = "tMPIVpoepMvBgJhKVyMqoYwxLzlBpgGqdiyCg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ANEO_2147922779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ANEO!MTB"
        threat_id = "2147922779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 b9 6b c6 45 ba b7 c6 45 bb c3 c6 45 bc 36 c6 45 bd 12 c6 45 be b7 c6 45 bf d9 c6 45 c0 45 c6 45 c1 2e c6 45 c2 e0 c6 45 c3 f6 c6 45 c4 89 c6 45 c5 7c c6 45 c6 55 c6 45 c7 db c6 45 c8 ee c6 45 c9 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPD_2147922816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPD!MTB"
        threat_id = "2147922816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ysGxHtqtZZiVkTmSs" ascii //weight: 3
        $x_2_2 = "oEuXZWLniTe" ascii //weight: 2
        $x_1_3 = "XTJsGFDoJtnNEF" ascii //weight: 1
        $x_1_4 = "MKjUfstdbmkWSxhwa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASU_2147922889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASU!MTB"
        threat_id = "2147922889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "COBHCobKcUSkRVnwYAfuWQqoZekukZ" ascii //weight: 1
        $x_1_2 = "sIolbdWIWQMaJRDMeBAIxwFwefDj" ascii //weight: 1
        $x_1_3 = "CzejBIUatJKXzYNBDBEHYrrGPLdiOtBxpl" ascii //weight: 1
        $x_1_4 = "KwmTrofViwqSMUdzfkkugCxyqxaOM" ascii //weight: 1
        $x_1_5 = "oPGacsCJYOAsZBVUVzHNUjDqZzVhhx" ascii //weight: 1
        $x_1_6 = "vmBARdNTDUHjbWKNjNOggRjwxJqo" ascii //weight: 1
        $x_1_7 = "zbvAElZsWkyzdWVgCisPSdAia" ascii //weight: 1
        $x_1_8 = "DhmFPQnmvJulzYARdAhPnbkTZFYXBu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASV_2147923269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASV!MTB"
        threat_id = "2147923269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PJtFQCgQdKYfUPwyylcqLncWROww" ascii //weight: 1
        $x_1_2 = "oKEXLQpSOApgdiGDyxRtAiXJUObJPMaBhW" ascii //weight: 1
        $x_1_3 = "ngJZtIKHgdRabvfIXctsYmIpsZEdB" ascii //weight: 1
        $x_1_4 = "GKXAYemnMnJEpCEvirDnZKkhjyxjjwfRXvPeelVaPLHoFBAbAdHajxLVsBhAzRtlHDAolnKoYkHbZMNuvKhUpTvDS" ascii //weight: 1
        $x_1_5 = "MZvNPSBvFBSbJWPJRHsCOFkkmLJC" ascii //weight: 1
        $x_1_6 = "fTHiMpQoUzMnTbRPjbcScKwiuDpnth" ascii //weight: 1
        $x_1_7 = "ufXHWKQwmvMHESAlOOTFkiftRkFZWbzAnP" ascii //weight: 1
        $x_1_8 = "fQVUtWYwScpenyYFJjvhqnENraVFcqgSQIdMwROCyDESWHIJoSKGONpTFqHjjVWyGdYevAYHYgZwjWqbWkFqrSSPc" ascii //weight: 1
        $x_1_9 = "NOeoSkUybhRqBiodllARDNlcSnHOfh" ascii //weight: 1
        $x_1_10 = "KIZHaXIVhrXUPXrFwWmNxXRicLlQEg" ascii //weight: 1
        $x_1_11 = "hGYRIfPkeQnISTvdZdHfToKpQyAedc" ascii //weight: 1
        $x_1_12 = "kgqUZGtYkcfegGylNzaXBAbTifjLqXzxzEKJczBcATpwRCWBznHDgVXgkodMlKikPCXqFjgpPbfczLvPCzMBSdmwk" ascii //weight: 1
        $x_1_13 = "RNiKSZcAMMgVgpKJglqkxyBqJyoIog" ascii //weight: 1
        $x_1_14 = "mVNIDwLbVgzVjhUimCPnCecVdNGulteSwa" ascii //weight: 1
        $x_1_15 = "PTROGTWUAhjrkcZmMEyQbYUFoIXBz" ascii //weight: 1
        $x_1_16 = "XovhOsMfsYBtLbBrByAyJUQqvnPyTUqljXGTDABFbOVPCRuvyXEuycRaPhAIAzUFzegRNplMZMrGuYhgjdHgExzBL" ascii //weight: 1
        $x_1_17 = "IqmTKcaTUTLGpuXnTlnwXmWLakZGvE" ascii //weight: 1
        $x_1_18 = "RAYBngsQnCCukqGpXwKcdnhOEuRsBcEqrk" ascii //weight: 1
        $x_1_19 = "xqdEAMRndUJquFTZTJNOXzkVcHYCP" ascii //weight: 1
        $x_1_20 = "SINWFUypXuVqGBpZumEIvHyyAEnhEMJNzNCzKPiIZNUnjTQtWKKJKBOrZCzngmMqsAiAalfxXUlTBIiuXGQUVyQzm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASW_2147923493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASW!MTB"
        threat_id = "2147923493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CbkjlOxNKRoVQKOPkGGxYJZwAVyUSD" ascii //weight: 1
        $x_1_2 = "waSjZNpfaqpgUmWeOZRfEwkZdnRBAy" ascii //weight: 1
        $x_1_3 = "lKXiMqfVzPLpCVtaDyewpOnxEnQKaOocqu" ascii //weight: 1
        $x_1_4 = "xhkOcjEdQGCmcCkMsWDkmrAWU" ascii //weight: 1
        $x_1_5 = "pJQMOabCxseALVMEuXjqGTzAzPEeBg" ascii //weight: 1
        $x_1_6 = "beqLRVvzALcPcikZyhTdzyBqPvMN" ascii //weight: 1
        $x_1_7 = "sASSMczzPWONbBwldVkzpoZBsqFx" ascii //weight: 1
        $x_1_8 = "fIYrzcaafbfURsdGxdFBgFLwSeFAFewsyD" ascii //weight: 1
        $x_1_9 = "vmpeUkZjYxMWnRlUWbxTLlpBntGnGz" ascii //weight: 1
        $x_1_10 = "AeIirCLaUyOQmnRUeGeQGWRoUemX" ascii //weight: 1
        $x_1_11 = "zejTFFYlZejhRWhGWJRXCnXngvWSGdfjRu" ascii //weight: 1
        $x_1_12 = "otefInYscJzmFXbNIZRiLpsMoQDIUaypHCKeobAByfomFkKzbRnayHXwLSYbRNDNwuTzwSGKEJgUXrWzZLrzvleet" ascii //weight: 1
        $x_1_13 = "iuWTXmtiObeJpyRJAwVsUorMQMacus" ascii //weight: 1
        $x_1_14 = "VwhVbkKFEKecRTxmxEyQAonmqRzW" ascii //weight: 1
        $x_1_15 = "ZIZHUwAGQSxcRqzjaSwpTxFzZJKjxR" ascii //weight: 1
        $x_1_16 = "cxCxbgMHAzolPmbqeVidEdaiKkbKOKaznH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASX_2147923792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASX!MTB"
        threat_id = "2147923792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "btPVHubEebEQXFuOEgLsNwAsqlVxzO" ascii //weight: 1
        $x_1_2 = "skejeVQdNFxQlHzOEkkosbWmZBkgjJ" ascii //weight: 1
        $x_1_3 = "FhUnChSJzshlIrkVFKbDhsLoiRAUOCQEEXfyX" ascii //weight: 1
        $x_1_4 = "GNceRhXTWDBmDkoJQwvbMXJeumkSYYPVZuMdkVmHu" ascii //weight: 1
        $x_1_5 = "ybMglESgolXuqYPaVuBgoEmPRdRWbL" ascii //weight: 1
        $x_1_6 = "HObNeVApOhsWrLIGJByMgemcmXgCcr" ascii //weight: 1
        $x_1_7 = "NaBHoTCZMHochffmFuDEWvdYlvgaUoxpvsBegtjpIG" ascii //weight: 1
        $x_1_8 = "QThJkemvdkUqggESNVAWNmgtFKmlXXvQqxNfAgUtuakczsGXbgm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASY_2147924284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASY!MTB"
        threat_id = "2147924284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TJCbwKupkuXuJaPjqARIozueCKLkKT" ascii //weight: 1
        $x_1_2 = "isbtRBHtdIxLEfBpFpnNfanAJKdIcRyIwA" ascii //weight: 1
        $x_1_3 = "GvEEhyyewRtcwkeRgZfUcpfUA" ascii //weight: 1
        $x_1_4 = "xpBwtAIYgiJjBrQppcDkdAdhqTdnxn" ascii //weight: 1
        $x_1_5 = "nnHQUqeDJNaFyRZfvPuqgCoYyDvU" ascii //weight: 1
        $x_1_6 = "MWxPrcEOWUwAuUMLvzyJyFwBYBznymKLhk" ascii //weight: 1
        $x_1_7 = "VXJQjflcmwqVSEendGSsqsdtzkUzLCHeAlOEE" ascii //weight: 1
        $x_1_8 = "vjFMBIUQKFYpydysJqwUrdsPEZXGsfOjKPBLYfdnyjZUIuEyhAx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_ASZ_2147924386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.ASZ!MTB"
        threat_id = "2147924386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cfuGHWKoHQSLnYWxjwroJbNHbbaO" ascii //weight: 1
        $x_1_2 = "TmTRVupkHUVwtAfyIhSSSPhXSRtH" ascii //weight: 1
        $x_1_3 = "rbeuYYwuxKgHgwndlXjSKqoCNlDRyyWigN" ascii //weight: 1
        $x_1_4 = "GPpooqJRckYUTlbFNYLPNALNyyPHc" ascii //weight: 1
        $x_1_5 = "rvfCpfWnqyHBprLBUNgPdMcfbzKXgg" ascii //weight: 1
        $x_1_6 = "uxaRymWpRVgLZIVFzahdfEtnvLjUpx" ascii //weight: 1
        $x_1_7 = "REiaywzwSFUGaDzDvhPgukBYHRSU" ascii //weight: 1
        $x_1_8 = "KkGYzfqWUPpSGRPEzBqpLMgQLLrXvjfsgN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAA_2147924807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAA!MTB"
        threat_id = "2147924807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KYBonHugLIVBVKZzKpGVhwhtjKCtGQ" ascii //weight: 1
        $x_1_2 = "dLYFbqEQjsxnRigQMqxwUJzvTJZhaq" ascii //weight: 1
        $x_1_3 = "NgjMhmQgrpuzOdGAHsHuiUNKQXmwRHeQVl" ascii //weight: 1
        $x_1_4 = "BnIyMhyvmlMUfdaQSYFTNUMTVJdwxddXHrnN" ascii //weight: 1
        $x_1_5 = "TuYGuCfFojXtPwYYCQNObqPhekDZXS" ascii //weight: 1
        $x_1_6 = "vmGUawIGnKdIgzjhzAGeyuLHCHDZ" ascii //weight: 1
        $x_1_7 = "uWbfbdMIwJAryWHaGMqXxLvjPEeZwuggHU" ascii //weight: 1
        $x_1_8 = "jTteROPEeineOQlKBpLCoonpyAHGqEEONrmn" ascii //weight: 1
        $x_1_9 = "seyOCsGZWcjadAKXxQHPauppVCTeLm" ascii //weight: 1
        $x_1_10 = "QPxJvOBkUvPAEaPraxErmyFcDxHh" ascii //weight: 1
        $x_1_11 = "ZBdbHeWDmbPOrRAOsoKMtIRKSWvzeKctXK" ascii //weight: 1
        $x_1_12 = "RUUqqljxeSWNUjHChgRTUqttvAHgPIqQNDnje" ascii //weight: 1
        $x_1_13 = "uwWseSKMEBnvoDnWORDzEeZcXMMn" ascii //weight: 1
        $x_1_14 = "wmDPyVHmZIhQcQKgPClOtLTvRIEj" ascii //weight: 1
        $x_1_15 = "iPEdQkzrhIRhVOlQbqLercEsZIseUg" ascii //weight: 1
        $x_1_16 = "uTyfjlRQreyiqsOjrpVGbuhDhvQJEePMWC" ascii //weight: 1
        $x_1_17 = "cuBySOryXLkAnqBVtkeAlPXbRzXp" ascii //weight: 1
        $x_1_18 = "gdaVutVVFHpzDYKqioCNjiNCddEGGfYYmP" ascii //weight: 1
        $x_1_19 = "CiiqpwcHNMoxQKMFwENSXtLWvbBqr" ascii //weight: 1
        $x_1_20 = "qmvVHBtNBsqjMkEpveJqOaEjVNHxxaUldl" ascii //weight: 1
        $x_1_21 = "TIKJedUweXQZJKqGfHXyBSDwueul" ascii //weight: 1
        $x_1_22 = "UauHBRjKHnDbTxBISVDeULLnegmz" ascii //weight: 1
        $x_1_23 = "fGyAphhNJsnIYTELPmTFFOPEthNfljDlBJ" ascii //weight: 1
        $x_1_24 = "QzzhhKPWOQnMciDxloUOoDnOBEPfDlIDH" ascii //weight: 1
        $x_1_25 = "OCeJFiIQoMKUOZSiEYZbcwZSJnNsrG" ascii //weight: 1
        $x_1_26 = "sirGKklQKRWYOFhUVAQHCGmlAgbE" ascii //weight: 1
        $x_1_27 = "LBdmQmpInrVWdhGGNjObmHSAGphCddcxte" ascii //weight: 1
        $x_1_28 = "KTNxHbknyKayTiQvtWyARBRLiyesN" ascii //weight: 1
        $x_1_29 = "JCgZvOdvTfumbJgveIqCyhvPrSNMyb" ascii //weight: 1
        $x_1_30 = "mFHBmZilkWshLWlQVbUTYYSYpvOg" ascii //weight: 1
        $x_1_31 = "aQsJRLyHGuYCmOTjgZwLCRGSjrTcernnzU" ascii //weight: 1
        $x_1_32 = "jSzmMdThFbqheMdgLcjoKKCAdHQSThbzhaMvFIv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPE_2147924953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPE!MTB"
        threat_id = "2147924953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "uUPquboQboe" ascii //weight: 3
        $x_2_2 = "GsdHtXKmgMpZOgnjxZBzeZzTMzXGJKdE" ascii //weight: 2
        $x_1_3 = "jGhVyDpcWQOuglNBX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAB_2147925133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAB!MTB"
        threat_id = "2147925133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TNgTFyBpxcFepuaMoXlUxPiFGPejGnnEOp" ascii //weight: 1
        $x_1_2 = "vGcUfGtYQvfspwzIEatPDQdBxKydRH" ascii //weight: 1
        $x_1_3 = "ORbKcNfSPMeSJuvUvARBMTKXpbUXg" ascii //weight: 1
        $x_1_4 = "gHFNuyDWikJVFIFfOKDOabkZPCdbQMUnzKdozdkwdCkNKbaNOxRDfdYDNLIFOaHfrYPRCPpkpKNpeAfBmgSTMEAXn" ascii //weight: 1
        $x_1_5 = "bJzAZvkKbTYMxABLTNEUpNdRAJgtqw" ascii //weight: 1
        $x_1_6 = "KbwGGzumKBTCARRakUAHEnuTdhlr" ascii //weight: 1
        $x_1_7 = "OOQyhFECxSIRsCjcBqjgsBhwgVXObErWCb" ascii //weight: 1
        $x_1_8 = "zgirpWUZACwVVcdJJNZmBcZUYLDxcIgQCHKG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPF_2147925296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPF!MTB"
        threat_id = "2147925296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {74 05 6a 07 59 cd 29 6a 01 68 15 00 00 40 6a 03 e8 cc 3b 00 00 83 c4 0c 6a 03 e8 d1 2b}  //weight: 3, accuracy: High
        $x_1_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPG_2147925297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPG!MTB"
        threat_id = "2147925297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {74 05 6a 07 59 cd 29 6a 01 68 15 00 00 40 6a 03 e8 cb 31 00 00 83 c4 0c 6a 03 e8}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPG_2147925297_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPG!MTB"
        threat_id = "2147925297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 48 8b 4d e0 03 4d f4 88 41 01 0f b6 45 ff 03 45 f4 89 45 f4 eb 92}  //weight: 3, accuracy: High
        $x_1_2 = {99 6a 0f 59 f7 f9 83 c2 0a 88 55 ff 0f b6 45 ff 03 45 f4 3b 45 ec 72 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPH_2147925489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPH!MTB"
        threat_id = "2147925489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {03 4d f4 88 41 01 0f b6 45 ff 03 45 f4 89 45 f4 eb 92}  //weight: 3, accuracy: High
        $x_1_2 = {99 6a 0f 59 f7 f9 83 c2 0a 88 55 ff 0f b6 45 ff 03 45 f4 3b 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPJ_2147925499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPJ!MTB"
        threat_id = "2147925499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "NjhfgyxretFgZxOafOKef" ascii //weight: 3
        $x_2_2 = "EfaEAcfarJTHp" ascii //weight: 2
        $x_1_3 = "dbznISjhatxBFMO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPJ_2147925499_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPJ!MTB"
        threat_id = "2147925499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "qZwWkFFnijnmgLqLLgrkcvH" ascii //weight: 3
        $x_2_2 = "SKfCJxECbeEkVcR" ascii //weight: 2
        $x_1_3 = "dUXHHoZetMeoCmjkvVusildeL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAD_2147925666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAD!MTB"
        threat_id = "2147925666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff ff 85 db 50 22 c7 85 ?? ?? ff ff 9d cd 00 b0 c7 85 ?? ?? ff ff fa f5 39 89 8b 85 ?? ?? ff ff f7 d8 83 f8 f7 77}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAC_2147925870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAC!MTB"
        threat_id = "2147925870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 45 fc 33 d2 f7 35 ?? ?? ?? 00 8b 45 14 8b 40 04 0f b6 04 10 50 8b 45 10 03 45 fc 8b 4d 14 8b 09 0f b6 04 01 50 e8 ?? ?? ?? ff 59 59 8b 4d f4 03 4d f8 88 01 eb}  //weight: 3, accuracy: Low
        $x_3_2 = {0f b6 45 fd 0f b6 4d fc 0b c1 89 45 ec 8a 45 ec 88 45 fb 8b 45 f0 d1 e0 89 45 f0 0f b6 45 fb 0b 45 f0 89 45 f0 eb}  //weight: 3, accuracy: High
        $x_2_3 = {0f b6 04 0a 33 c6 69 f0 ?? ?? ?? 01 42 83 fa 04 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_BAG_2147926083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAG!MTB"
        threat_id = "2147926083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 45 fc 40 89 45 fc 8b 45 fc 3b 45 0c 73 3b 8b 45 10 03 45 fc 33 d2 f7 35 ?? ?? ?? ?? 8b 45 14 8b 40 04 0f b6 04 10 50 8b 45 10 03 45 fc 8b 4d 14 8b 09 0f b6 04 01 50 e8 ?? ?? ?? ?? 59 59 50 8d 4d e4 e8 ?? ?? ?? ?? eb}  //weight: 4, accuracy: Low
        $x_1_2 = {99 f7 f9 a5 a5 a5 8b 4d fc 5f 5e 5b 8b ?? c1 [0-4] 2d 2c 01 00 00 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAE_2147926133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAE!MTB"
        threat_id = "2147926133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {c6 45 fe 00 8a 45 fe 88 45 fc 0f b6 45 fd 0f b6 4d fc 23 c1 74 06 83 65 ec 00 eb 0d 0f b6 45 fd 0f b6 4d fc 0b c1 89 45 ec 8a 45 ec 88 45 fb 8b 45 f0 d1 e0 89 45 f0 0f b6 45 fb 0b 45 f0 89 45 f0 eb}  //weight: 4, accuracy: High
        $x_1_2 = {c6 45 ff 00 8a 45 ff 88 45 fd 33 c0 40 8b 4d f4 d3 e0 23 45 0c 74 06 c6 45 fe 01 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAF_2147926134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAF!MTB"
        threat_id = "2147926134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 14 78 8d 87 ?? ?? 00 00 0f b7 c8 8b c1 23 c2 03 c0 2b c8 03 ca 0f b7 f1 8d 04 17 33 d2 6a 19 59 f7 f1 8b ca d3 e6 01 75 ec 47 39 7b 10 77}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPK_2147926229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPK!MTB"
        threat_id = "2147926229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "oaxzKLbFAWPbgQsGxHF" ascii //weight: 3
        $x_2_2 = "pRbrVbWKlMoQHKLUiDamzX" ascii //weight: 2
        $x_1_3 = "ZTQmvTeNzHtmZtDKiWRkBjmShtLWMv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPX_2147926818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPX!MTB"
        threat_id = "2147926818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 40 89 45 fc 8b 45 fc 3b 45 0c 73 3b 8b 45 10 03 45 fc 33 d2 f7 35 ?? ?? ?? ?? 8b 45 14 8b 40 04 0f b6 04 10 50 8b 45 10 03 45 fc 8b 4d 14 8b 09 0f b6 04 01 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAH_2147926888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAH!MTB"
        threat_id = "2147926888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "nyWUSKRQYNWPaKIztFbqMfoTLYqhlnnCWh" ascii //weight: 2
        $x_1_2 = "FBjCFUXxrondhtaZbEoNGHZDDvxRg" ascii //weight: 1
        $x_1_3 = "BZxrLtraipEnBtTNQofRIiwCgsARp" ascii //weight: 1
        $x_1_4 = "BbABHeFHnFViGSJKeXyeFFlGJMOd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GQX_2147927075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GQX!MTB"
        threat_id = "2147927075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 0d 0f b6 45 ?? 0f b6 4d ?? 0b c1 89 45 ?? 8a 45 ?? 88 45 ?? 8b 45 ?? d1 e0 89 45 ?? 0f b6 45 ?? 0b 45 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAI_2147927352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAI!MTB"
        threat_id = "2147927352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 45 fc 50 e8 ?? ?? ?? ff 59 59 8b 4d 14 8b 49 04 0f b6 04 01 50 8b 45 10 03 45 fc 8b 4d 14 8b 09 0f b6 04 01 50 e8 ?? ?? ?? ff 59 59 50 8d 4d e4 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAJ_2147927353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAJ!MTB"
        threat_id = "2147927353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ujdlZNELoqcDqhJahjTkvju" ascii //weight: 3
        $x_1_2 = "ljTqfAzTFsLzNpnCDgFsdRJjXCguGd" ascii //weight: 1
        $x_1_3 = "kpGceMMSMkYmpFqbkvXBDTZGyRHM" ascii //weight: 1
        $x_3_4 = "yFySLrqRKTWUiCPLWKreHaWHhilhY" ascii //weight: 3
        $x_1_5 = "vwrEVFVRTEewCNVehhsSoDlxQRCGKg" ascii //weight: 1
        $x_1_6 = "hTlOaYPpICEAeWVaJZxBTsUxSfgVIj" ascii //weight: 1
        $x_3_7 = "nEYLrLqtyBfyRKSwhsTJrmDYrHerCV" ascii //weight: 3
        $x_1_8 = "xzScRCjZEhSGRMrObXeLOppUoitt" ascii //weight: 1
        $x_1_9 = "ehWogYYoILfztmronSNZdLjVqqDEvoPMqv" ascii //weight: 1
        $x_3_10 = "FGoGaIaIZvFBNevJWNYbyvA" ascii //weight: 3
        $x_1_11 = "GUVwvwwhpGTSlQoRzItzMfYgl" ascii //weight: 1
        $x_1_12 = "QpsQXyMgRrMARzQZVFWpDWcWJoiQFvIkqmHcNaJYRavJNExpkbNENxJcPuvtdvHctUvRvcOlAdZgopmFfDikeBtKe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_BAK_2147927492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAK!MTB"
        threat_id = "2147927492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {51 8b 45 08 33 d2 f7 75 0c 89 45 fc 8b 45 0c 0f af 45 fc 8b 4d 08 2b c8 89 4d f8 8b 45 f8 8b e5 5d c3}  //weight: 3, accuracy: High
        $x_2_2 = {ff 34 81 ff 34 b7 e8 ?? ?? ?? ?? 83 c4 10 89 04 b7 46 3b f3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NA_2147927650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NA!MTB"
        threat_id = "2147927650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec a1 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 74 0d ff 75 10 ff 75 0c ff 75 08 ff d0 5d c3}  //weight: 2, accuracy: Low
        $x_1_2 = "RwSAYMUkAVDDerwiqDLPmZTpkkyy" ascii //weight: 1
        $x_1_3 = "giypBXSsoYHdTdGrlVXGZHHgObLFmy" ascii //weight: 1
        $x_1_4 = "zDmLVbPIjRpSLGeOXoS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAL_2147927736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAL!MTB"
        threat_id = "2147927736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 48 fe 8b d6 e8 ?? ?? ff ff 03 c7 b9 c4 00 00 00 99 f7 f9 46 8b fa 83 fe 04}  //weight: 3, accuracy: Low
        $x_2_2 = {ff 03 04 b5 ?? ?? ?? ?? b9 c4 00 00 00 99 f7 f9 89 14 b5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAM_2147927830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAM!MTB"
        threat_id = "2147927830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {45 fc 50 e8 ?? ?? ?? ff 59 59 8b 4d ?? 8b 49 04 0f b6 04 01 50 8b 45 ?? 03 45 fc 8b 4d ?? 8b 09 0f b6 04 01 50 e8 ?? ?? ?? ff 59 59 50 8d 4d e4 e8}  //weight: 3, accuracy: Low
        $x_2_2 = {55 8b ec 51 51 8b 45 08 33 d2 f7 75 0c 89 45 fc 8b 45 0c 0f af 45 fc 8b 4d 08 2b c8 89 4d f8 8b 45 f8}  //weight: 2, accuracy: High
        $x_2_3 = {8b 4d 08 ff 34 81 ff 34 b7 e8 ?? ?? ?? ?? 83 c4 10 89 04 b7 46 3b f3 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_NB_2147927855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NB!MTB"
        threat_id = "2147927855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BFzSwUgOueyxlhVugnXnmXALeDuejFJFBq" ascii //weight: 2
        $x_1_2 = "jsrBHGtONLnukmcwRqSCrW" ascii //weight: 1
        $x_1_3 = "YgiurRHdogLExkDHWcrPCrwKgRSZPGaOZYjqxxgar" ascii //weight: 1
        $x_1_4 = "GHRmfsusNOlDZdJGcETndiTYImGixzZbLYOSmQFgNyf" ascii //weight: 1
        $x_1_5 = "mFpULICGtSQbYbEDxOfJMwxuwBceHwaPfuzZmamOEkr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BAN_2147928321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BAN!MTB"
        threat_id = "2147928321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {59 33 d2 8b c6 f7 f1 8b 45 08 ff 34 ?? ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec ?? 8b 45 08 03 45 0c 89 45}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 08 23 45 0c 89 45 f4 8b 45 08 23 45 0c 89 45}  //weight: 1, accuracy: High
        $x_3_4 = {2b c1 0f af 45 ?? 0f b6 4d ?? 8b 55 ?? 0f af d1 03 c2 8b 4d ?? 2b c8 0f b6 45}  //weight: 3, accuracy: Low
        $x_2_5 = {2b c2 0f af 45 ?? 0f b6 55 ?? 8b 75 ?? 0f af f2 03 c6 03 c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_BH_2147928780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BH!MTB"
        threat_id = "2147928780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HooGqDnbMHZuzKSblLytJUhlexaJEr" ascii //weight: 2
        $x_1_2 = "joRcJBpCtmXYbILeOovYrFHMsqLG" ascii //weight: 1
        $x_1_3 = "nBPRXPpNQIecFUhaoiMuCgBpLHmmzu" ascii //weight: 1
        $x_1_4 = "PRrkEOWsLxYKhuUyLvgrHRonWQwXMvlsax" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BI_2147928890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BI!MTB"
        threat_id = "2147928890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b c8 0f b6 45 ?? 0f af 45 ?? 03 c8 89 4d}  //weight: 3, accuracy: Low
        $x_2_2 = {2b c8 0f af 4d ?? 03 d1 0f b6 4d}  //weight: 2, accuracy: Low
        $x_2_3 = "HiatDNfVFQNrULhJnElwgpwldVf" ascii //weight: 2
        $x_1_4 = "IbYasSFUrXUUdqCsdfpfAAfocBBWfxKQU" ascii //weight: 1
        $x_1_5 = "ltbNNXbmPKtqGieUEJqKhoUoROXGzthItD" ascii //weight: 1
        $x_1_6 = "zyoVLUAunyDFAUTVwadKAylIAvugC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_BK_2147929113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BK!MTB"
        threat_id = "2147929113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 45 fb 0f af 45 f4 2b c8}  //weight: 2, accuracy: High
        $x_2_2 = {2b d1 2b d0 ff 34 97 ff 34 b3 e8}  //weight: 2, accuracy: High
        $x_1_3 = {0f af c8 0f b6 45 fd 2b d1}  //weight: 1, accuracy: High
        $x_5_4 = {2b c8 0f b6 45 fe 0f af 45 f4 03 c8 03 4d e4 ff 34 8f ff 34 b3 e8 ?? ?? ?? ?? 89 04 b3 46 0f b6 45 ff 59 59 8b 4d ec 2b c8 0f af 4d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_NE_2147929277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NE!MTB"
        threat_id = "2147929277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 44 24 a8 e2 91 93 b6 45 04 dc 52 b4 a8 03 e5 f8 ae dc c5 ed}  //weight: 2, accuracy: High
        $x_1_2 = {0f 94 c2 2b d1 33 c9 3b d0 8b 45 e8 0f 9f c1 33 d2 8b 44 85 b0 3b c1 8b 45 e8 0f 94 c2 33 c9 8b 44 85 b0 3b d0 0f 9c c1}  //weight: 1, accuracy: High
        $x_1_3 = {5d 13 30 87 f3 35 95 59 89 d4 fa 2c e6 ec 8c ab a5 91 b9 ff 25 bd 20 45 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NC_2147929278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NC!MTB"
        threat_id = "2147929278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FMuzOLkjjISWrlznbGkCduaeZdoKiMVYaV" ascii //weight: 2
        $x_1_2 = "LsmKFCOTBauawwWqadcbVrKuynoPycFlMOq" ascii //weight: 1
        $x_1_3 = "sCIKSgBYaEYkblOOPdePtQIqFzAzJAtwOHDSHVtNLNO" ascii //weight: 1
        $x_1_4 = "zhIDgWocfHUkFqyqwYGUZwWWygqs" ascii //weight: 1
        $x_1_5 = "AkSApgmIeMLhVBWvuXMOEhvljNuonIXcMJIiLJMRNYW" ascii //weight: 1
        $x_1_6 = "ggvEebNqzlJuZAMrqTyoCffvfko" ascii //weight: 1
        $x_1_7 = "EgqdLkAeNANlkQGatRbLNttNiYBI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NG_2147929284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NG!MTB"
        threat_id = "2147929284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b4 31 d7 43 28 50 6b 99 d6 6e 84 12 a2 fc b7 0c a4 30 04 a7 35 5e b8 77 35}  //weight: 2, accuracy: High
        $x_1_2 = {55 32 cd d2 45 6b 3a 39 78 c0 35 17 2c 98 30 fb bf 81 7d e4 05 3c 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 ff 47 8b 4d 88 33 d2 8b 45 d4 3b c8 0f 9d c2 4a 75 03 8b 45 d0 8b 45 d8 ba 96 a7 00 00 8b 45 d8 33 c9 8b 45 ec 2b d0 8b 45 e8 3b c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BM_2147929362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BM!MTB"
        threat_id = "2147929362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c6 99 52 50 e8}  //weight: 5, accuracy: High
        $x_5_2 = {83 ec 30 53 56 57 8b f1 89 65 f0 33 db 89 75 e8 56 8d 4d d0 8b fb e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BN_2147929470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BN!MTB"
        threat_id = "2147929470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 45 ff 0f b6 55 ?? 0f af c8 0f b6 45 ff 0f af d0 2b d1 03 55 ?? 0f af 55 ?? 0f b6 45}  //weight: 10, accuracy: Low
        $x_10_2 = {89 75 fc 33 d2 c7 45 f8 ?? ?? ?? ?? 8b 4d f8 8b 45 fc f7 f1 0f af 45 f8 8b 4d fc 2b c8 ff 34 8f ff 34 b3 e8 ?? ?? ?? ?? 89 04 b3 46 8b 45}  //weight: 10, accuracy: Low
        $x_5_3 = {8b 4d 14 8b 09 0f b6 04 01 50 e8}  //weight: 5, accuracy: High
        $x_5_4 = {2b c1 8b 4d 14 8b 49 04 0f b6 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_NH_2147929537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NH!MTB"
        threat_id = "2147929537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 07 8b 45 a0 48 89 45 a0 83 7d a0 00 7c 38 8b 45}  //weight: 2, accuracy: High
        $x_1_2 = {55 8b ec 8b 45 0c 53 56 8b 75 08 33 db 2b c6 83 c0 03 c1 e8 02 39 75 0c 57 1b ff f7 d7 23 f8 76 10}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 e4 40 89 45 e4 83 7d e4 04 7d 10 8b 45 e4 c7 84 85 b0 fc ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BP_2147929603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BP!MTB"
        threat_id = "2147929603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 75 f8 33 d2 c7 45 fc ?? 00 00 00 8b 4d fc 8b 45 f8 f7 f1 0f af 45 fc 8b 4d f8 2b c8 8b 45 08 ff 34 88 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72}  //weight: 10, accuracy: Low
        $x_5_2 = {0f af d1 03 c2 8b 8d ?? ?? ff ff 03 c8 0f b6 85 ?? ?? ff ff 0f af 85}  //weight: 5, accuracy: Low
        $x_5_3 = {0f af c8 0f b6 45 ?? 0f af d0 0f b6 45 ?? 2b d1 03 d0}  //weight: 5, accuracy: Low
        $x_5_4 = {2b d0 0f b6 45 fc 0f b6 4d fe 0f af d0 0f b6 45 fc 0f af c8 03 d1}  //weight: 5, accuracy: High
        $x_5_5 = {0f af c8 0f b6 45 ?? 0f af 45 ?? 2b d1 2b d0 03 55}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_NQ_2147929605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NQ!MTB"
        threat_id = "2147929605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 58 6b c0 00 8b 84 05 ?? ff ff ff 89 45 cc 8b 45 cc}  //weight: 1, accuracy: Low
        $x_2_2 = {6a 04 58 c1 e0 00 8b 84 05 cc fd ff ff 48 6a 04 59 c1 e1 00 89 84 0d cc fd ff ff 6a 04 58 c1 e0 00}  //weight: 2, accuracy: High
        $x_1_3 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 0c ff ff ff 48 6a 04 59 6b c9 00 89 84 0d 0c ff ff ff 6a 04 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BQ_2147929621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BQ!MTB"
        threat_id = "2147929621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 da 1b d2 33 c9 f7 da 3b d0 8b 45}  //weight: 5, accuracy: High
        $x_5_2 = {33 d2 8b ce 2b c8 8b 45 ?? 3b c8 8b 45}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJ_2147929700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJ!MTB"
        threat_id = "2147929700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 07 8b 45 d8 48 89 45 d8 83 7d d8 00 7c 11 8b 45 d8}  //weight: 1, accuracy: High
        $x_2_2 = {eb 07 8b 45 c8 40 89 45 c8 83 7d c8 04 7d 10 8b 45 c8}  //weight: 2, accuracy: High
        $x_1_3 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 02 7d 0d 8b 45 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NP_2147929701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NP!MTB"
        threat_id = "2147929701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 58 6b c0 00 8b 44 05 94 40 6a 04 59 6b c9 00 89 44 0d 94 6a 04 58 6b c0 00 83 7c 05 94 02}  //weight: 1, accuracy: High
        $x_2_2 = {eb 19 6a 04 58 d1 e0 8b 84 05 ?? ?? ff ff 48 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0}  //weight: 2, accuracy: Low
        $x_1_3 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 00 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NR_2147929742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NR!MTB"
        threat_id = "2147929742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 f8 40 89 45 f8 83 7d f8 01 7d 10 8b 45 f8 c7 84 85 ?? ?? ff ff ff ff ff ff eb e3 c7 45 f8}  //weight: 1, accuracy: Low
        $x_2_2 = {6a 04 58 6b c0 00 c7 44 05 88 ?? ff ff ff eb 15 6a 04 58 6b c0 00 8b 44 05 88 48 6a 04 59 6b c9 00 89 44 0d 88 6a 04 58 6b c0 00}  //weight: 2, accuracy: Low
        $x_1_3 = {eb 15 6a 04 58 6b c0 00 8b 44 05 88 48 6a 04 59 6b c9 00 89 44 0d 88 6a 04 58 6b c0 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPL_2147929750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPL!MTB"
        threat_id = "2147929750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "MpAVIvjhOiILZ" ascii //weight: 3
        $x_2_2 = "zHlexAfLBOqNzeHCfQgZb" ascii //weight: 2
        $x_1_3 = "QgVpkNQNUSWVOlStsSlpdiYnN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPO_2147929955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPO!MTB"
        threat_id = "2147929955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "dwbqcZtZMxXIM" ascii //weight: 3
        $x_2_2 = "cNQPaUBBoeOyXLJIGtNEPXn" ascii //weight: 2
        $x_1_3 = "kkQrLxofpKCpgcbszeeYwOhwA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NV_2147930144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NV!MTB"
        threat_id = "2147930144"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 8b 51 08 b8 ff ff ff 3f 2b 11 c1 fa 02 8b ca d1 e9 2b c1 3b c2 73 04}  //weight: 2, accuracy: High
        $x_1_2 = {55 8b ec 51 51 83 65 fc 00 56 51 8b f1 e8 ?? ?? ff ff 59 8b c6 5e 8b e5 5d c3 55}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 0d 8b 0a 8b 06 c7 04 88 ?? ?? ff ff ff 02 83 3a 01 7c ee}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NW_2147930145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NW!MTB"
        threat_id = "2147930145"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 83 a5 f4 fe ff ff 00 6a 04 58 6b c0 00 8b 44 05 fc}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 94 40 89 45 94 83 7d 94 01 7d 0d 8b 45 94}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ff ff ff 8d 44 00 02 39 45 f4}  //weight: 1, accuracy: Low
        $x_1_4 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 03 7d 10 8b 45 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BR_2147930167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BR!MTB"
        threat_id = "2147930167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {59 33 d2 8b c6 f7 f1 8b 45 08 ff 34 ?? ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72}  //weight: 6, accuracy: Low
        $x_2_2 = {55 8b ec 53 56 57 8d 3c 09 33 f6}  //weight: 2, accuracy: High
        $x_2_3 = {40 6a 04 59 d1 e1 89 84 0d}  //weight: 2, accuracy: High
        $x_6_4 = {0f b6 94 15 ?? ?? ff ff 0f be 54 15 ?? 23 ca 2b c1 8b 4d ?? 0f b6 8c 0d ?? ?? ff ff 88 44 0d}  //weight: 6, accuracy: Low
        $x_2_5 = {8b 45 fc 8b 00 40 8b 4d fc 89 01 8b 45 fc 83 38 00 7f}  //weight: 2, accuracy: High
        $x_2_6 = {ff 6b 89 85 ?? ?? ff ff 6b 85 ?? ?? ff ff 6c 89 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_NY_2147930316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NY!MTB"
        threat_id = "2147930316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 08 8b 45 e8 40 40 89 45 e8 83 7d e8 24 0f 83 ?? ?? 00 00 33 c0 40 6b c0 00}  //weight: 2, accuracy: Low
        $x_1_2 = {eb 07 8b 45 98 40 89 45 98 83 7d 98 01 7d 10 8b 45 98 c7 84 85}  //weight: 1, accuracy: High
        $x_1_3 = {eb 1b 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 03 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NLA_2147930317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NLA!MTB"
        threat_id = "2147930317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 15 6a 04 58 6b c0 00 8b 44 05 cc 48 6a 04 59 6b c9 00 89 44 0d cc 6a 04 58 6b c0 00}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 02 7d 0d 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_3 = {33 ff 33 db 8b c3 8d 4c 24 20 33 c7 0b c6 99 52 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BS_2147930774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BS!MTB"
        threat_id = "2147930774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 c7 45 fc ?? 00 00 00 8b 4d fc 8b 45 f8 f7 f1 0f af 45 fc 8b 4d f8 2b c8 ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f4 03 45 f0 59 59 3b f0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NLB_2147931039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NLB!MTB"
        threat_id = "2147931039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 03 7d 10 8b 45 fc}  //weight: 2, accuracy: High
        $x_1_2 = {eb 08 8b 45 dc 40 40 89 45 dc 83 7d dc 20}  //weight: 1, accuracy: High
        $x_1_3 = {eb 19 6a 04 58 d1 e0 8b 84 05 ?? ?? ff ff 48 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BT_2147931134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BT!MTB"
        threat_id = "2147931134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 c7 45 f4 ?? 00 00 00 8b 4d f4 8b 45 f8 f7 f1 0f af 45 f4 8b 4d f8 2b c8 ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 fc 03 45 ?? 59 59 3b f0}  //weight: 10, accuracy: Low
        $x_5_2 = {03 45 e8 89 45 f4 6b 4d f4 24 6b 45 f4 25 2b c8 03 4d f8 ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f0 03 45 ec 59 59 3b f0}  //weight: 5, accuracy: Low
        $x_5_3 = {89 75 f4 33 d2 c7 45 f8 ?? 00 00 00 8b 45 f8 89 45 e8 8b 4d f8 8b 45 f4 f7 f1 89 45 fc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_GPPA_2147931197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPPA!MTB"
        threat_id = "2147931197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "qlFDSjdfIGNVwmPDQ" ascii //weight: 3
        $x_2_2 = "JgekAxJmQzGpGQwxb" ascii //weight: 2
        $x_1_3 = "mzyYRFafVhfHNBDdDQfPPqu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BU_2147931310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BU!MTB"
        threat_id = "2147931310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {59 33 d2 8b c6 f7 f1 ff 34 97 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 fc 03 45 f8 59 59 3b f0 72}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 81 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BV_2147931341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BV!MTB"
        threat_id = "2147931341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 8b 45 ?? 2b ca 03 4d ?? ff 34 8f ff 34 b0 e8 ?? ?? ff ff 59 59 8b 4d ?? 89 04 b1 46 8b 45 ?? 03 c3 3b f0}  //weight: 10, accuracy: Low
        $x_5_2 = {8b 45 08 8a 1c 07 8b c7 99 f7 7d ?? 8b f2 8a d1 8a cb e8 ?? ?? 00 00 8b 4d 10 8a 14 0e 8a c8 e8}  //weight: 5, accuracy: Low
        $x_5_3 = {56 0f b6 f1 0f b6 c2 8b c8 23 ce 03 c9 2b c1 03 c6 5e c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_NLF_2147931428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NLF!MTB"
        threat_id = "2147931428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 08 8b 45 e0 40 40 89 45 e0 83 7d e0 1e}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 80 40 89 45 80 83 7d 80 03 7d 10 8b 45 80}  //weight: 1, accuracy: High
        $x_1_3 = {eb d7 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 40 6a 04 59 6b c9 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NLE_2147931805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NLE!MTB"
        threat_id = "2147931805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec 01 7d 0d 8b 45 ec}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 f4 48 89 45 f4 83 7d f4 f6}  //weight: 1, accuracy: High
        $x_1_3 = {50 33 d2 42 33 c9 e8 ?? ?? ff ff 59 59 8b f0 8d bd ?? ff ff ff a5 a5 a5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NLI_2147932023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NLI!MTB"
        threat_id = "2147932023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb e6 6a 04 58 6b c0 00 6a 04 59 6b c9 00}  //weight: 2, accuracy: High
        $x_2_2 = {eb 04 83 65 c8 00 8b 45 fc 3b 45 c8 75 09}  //weight: 2, accuracy: High
        $x_1_3 = {40 6a 04 59 c1 e1 00 89 84 0d ?? ?? ff ff 6a 04 58 c1 e0 00}  //weight: 1, accuracy: Low
        $x_1_4 = {50 33 d2 42 33 c9 e8 ?? ?? ff ff 59 59 8b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BW_2147932123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BW!MTB"
        threat_id = "2147932123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc f7 f1 0f af 45 f8 89 45 f8 69 4d f8 ?? 00 00 00 69 45 f8 ?? 00 00 00 2b c8 03 4d ec ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f4 03 45 f0 59 59 3b f0 72}  //weight: 10, accuracy: Low
        $x_10_2 = {f7 f1 89 45 f8 8b 45 ec 2d ?? 00 00 00 89 45 ?? 8b 45 ec 0f af 45 f8 89 45 ec 69 45 f8 ?? 00 00 00 89 45 f8 8b 45 ec 8b 4d fc 2b c8 2b 4d f8 ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f4 03 45 ?? 59 59 3b f0 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Neoreblamy_NLJ_2147932246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NLJ!MTB"
        threat_id = "2147932246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 b0 48 89 45 b0 83 7d b0 00 7c 2e}  //weight: 2, accuracy: High
        $x_1_2 = {6a 04 59 6b c9 00 0f af 84 0d ?? fe ff ff 6a 04 59 c1 e1 00}  //weight: 1, accuracy: Low
        $x_1_3 = {eb da 6a 04 58 6b c0 00 c7 44 05 a0 ?? ff ff ff eb 15 6a 04 58 6b c0 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NLK_2147932247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NLK!MTB"
        threat_id = "2147932247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 08 8b 45 e4 40 40 89 45 e4 83 7d e4 06}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 ec 48 89 45 ec 83 7d ec 00 7c 10 8b 45 ec}  //weight: 1, accuracy: High
        $x_1_3 = {6a 04 58 6b c0 00 8b 44 05 84 89 85 ?? ?? ff ff 6a 04 58 c1 e0 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BX_2147932317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BX!MTB"
        threat_id = "2147932317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 8b c6 f7 f1 ff 34 97 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f8 03 45 fc 59 59 3b f0 72}  //weight: 5, accuracy: Low
        $x_5_2 = {33 d2 8b c6 f7 f1 8b 45 f8 ff 34 97 ff 34 b0 e8 ?? ?? ff ff 59 59 8b 4d f8 89 04 b1 46 8b 45 f4 03 c3 3b f0 72}  //weight: 5, accuracy: Low
        $x_5_3 = {59 33 d2 8b c6 f7 f1 8b 45 08 ff 34 ?? ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72}  //weight: 5, accuracy: Low
        $x_4_4 = {8b 45 08 8b d6 8b 0c b3 83 e2 3f 8b 14 ?? ?? ?? ?? ff ff 89 04 b3 46 3b f7 72}  //weight: 4, accuracy: Low
        $x_1_5 = {8b c1 23 c2 03 c0 2b c8 8d 04 0a c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_NLM_2147932348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NLM!MTB"
        threat_id = "2147932348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 80 40 89 45 80 83 7d 80 04 7d 10 8b 45 80}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 90 48 89 45 90 83 7d 90 e7}  //weight: 1, accuracy: High
        $x_1_3 = {eb 1b 6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 c1 e1 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_GPPE_2147932502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPPE!MTB"
        threat_id = "2147932502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "jyFGdXgiNItjlGbsnGUGwmA" ascii //weight: 3
        $x_2_2 = "rjbkYPiCCeKFRxcHQYPh" ascii //weight: 2
        $x_1_3 = "hdxYONerVZJfdbwYOXKa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BY_2147932584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BY!MTB"
        threat_id = "2147932584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 2b ca 03 4d ec ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 fc 03 45 f0 59 59 3b f0 72}  //weight: 10, accuracy: Low
        $x_10_2 = {2b c8 03 4d ec ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f4 03 45 f0 59 59 3b f0 72}  //weight: 10, accuracy: Low
        $x_10_3 = {2b c8 2b 4d f8 ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f4 03 45 f0 59 59 3b f0 72}  //weight: 10, accuracy: Low
        $x_5_4 = {ff ff 89 04 b3 46 8b 45 fc 03 45 f0 59 59 3b f0 72}  //weight: 5, accuracy: High
        $x_5_5 = {2b c8 2b 4d ?? ff 34 8f ff 34 b3 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_GPPF_2147932612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.GPPF!MTB"
        threat_id = "2147932612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "miHUdngPLwfuuoSzOsVXlcr" ascii //weight: 3
        $x_2_2 = "bYLBIqioKjYHWGhzIJ" ascii //weight: 2
        $x_1_3 = "VxkVnKbFOBLfbNnK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NLQ_2147932967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NLQ!MTB"
        threat_id = "2147932967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 07 8b 45 d8 40 89 45 d8 83 7d d8 02 7d 10 8b 45 d8}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 e4 48 89 45 e4 83 7d e4 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFA_2147933062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFA!MTB"
        threat_id = "2147933062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 03}  //weight: 2, accuracy: High
        $x_1_2 = {33 c0 40 c1 e0 00 0f b6 84 05 ?? ff ff ff 83 c8 53 33 c9 41 c1 e1 00 0f b6 8c 0d ?? ff ff ff 83 e1 53 2b c1 33 c9 41 6b c9 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFB_2147933063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFB!MTB"
        threat_id = "2147933063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 90 fd ff ff 48 6a 04 59 6b c9 00 89 84 0d 90 fd ff ff 6a 04 58 6b c0 00}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 e4 40 89 45 e4 83 7d e4 01 7d 0d 8b 45 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_BZ_2147933245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.BZ!MTB"
        threat_id = "2147933245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 8b 45 ?? 03 4d ?? ff 34 8b ff 34 b0 e8 ?? ?? ff ff 59 59 8b 4d ?? 89 04 b1 46 8b 45 ?? 03 c7 3b f0 72}  //weight: 10, accuracy: Low
        $x_10_2 = {33 d2 f7 35 ?? ?? ?? ?? 8b 45 14 8b 40 04 0f b6 04 10 50 8b 45 10 03 45 fc 8b 4d 14 8b 09 0f b6 04 01 50 e8 ?? ?? ff ff 59 59 50 8d 4d e4 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFC_2147933350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFC!MTB"
        threat_id = "2147933350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 04 59 c1 e1 00 8b 8c 0d ?? ?? ff ff 6a 04 5a c1 e2 00 8b 94 15 ?? ?? ff ff 4a 6a 04 5e c1 e6 00}  //weight: 2, accuracy: Low
        $x_1_2 = {eb 07 8b 45 ac 40 89 45 ac 83 7d ac 03 7d 10 8b 45 ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFD_2147933492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFD!MTB"
        threat_id = "2147933492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7d 64 83 65 e0 00 eb 07 8b 45 e0 40 89 45 e0}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 01 7d 10 8b 45 c0}  //weight: 1, accuracy: High
        $x_1_3 = {7d 45 83 65 e8 00 eb 07 8b 45 e8 40 89 45 e8 81 7d e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFE_2147933630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFE!MTB"
        threat_id = "2147933630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 07 8b 45 e8 40 89 45 e8 83 7d e8 01 7d 10 8b 45 e8}  //weight: 2, accuracy: High
        $x_1_2 = {eb 08 8b 45 d8 40 40 89 45 d8 83 7d d8 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFG_2147933631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFG!MTB"
        threat_id = "2147933631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? ff ff ff 48 6a 04 59 6b c9 00 89 84 0d ?? ff ff ff 6a 04 58 6b c0 00}  //weight: 2, accuracy: Low
        $x_1_2 = {eb 07 8b 45 f8 40 89 45 f8 83 7d f8 01 7d 10 8b 45 f8}  //weight: 1, accuracy: High
        $x_1_3 = {eb e3 6a 04 58 6b c0 00 8b 84 05 ?? ff ff ff 89 85 ?? ?? ff ff 6a 04 58 c1 e0 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFK_2147933847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFK!MTB"
        threat_id = "2147933847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 07 8b 45 e8 40 89 45 e8 83 7d e8 04 7d 10 8b 45 e8}  //weight: 2, accuracy: High
        $x_1_2 = {7d 7b 83 65 b8 00 eb 07 8b 45 b8 40 89 45 b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFK_2147933847_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFK!MTB"
        threat_id = "2147933847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 8c 40 89 45 8c 83 7d 8c 01 7d 0d 8b 45 8c}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 cc 48 89 45 cc 83 7d cc e9}  //weight: 1, accuracy: High
        $x_1_3 = {eb 1b 6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 c1 e1 00 89 84 0d ?? ?? ff ff 6a 04 58 c1 e0 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFL_2147933848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFL!MTB"
        threat_id = "2147933848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? fe ff ff 40 6a 04 59 6b c9 00 89 84 0d ?? fe ff ff 6a 04 58 6b c0 00}  //weight: 1, accuracy: Low
        $x_2_2 = {eb 07 8b 45 94 40 89 45 94 83 7d 94 01 7d 10 8b 45 94}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CA_2147934007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CA!MTB"
        threat_id = "2147934007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 f1 0f af 45 fc 8b 4d f8 2b c8 8b 45 f4 ff 34 8f ff 34 b0 e8 ?? ?? ff ff 59 59 8b 4d f4 89 04 b1 46 8b 45 f0 03 c3 3b f0 72}  //weight: 5, accuracy: Low
        $x_4_2 = {0f b6 04 10 50 8b 45 10 03 45 f8 8b 4d 14 8b 09 0f b6 04 01 50 e8 ?? ?? ff ff 59 59 8b 4d f0 03 4d f4 88 01 eb}  //weight: 4, accuracy: Low
        $x_1_3 = {8b 45 10 03 45 f8 33 d2 f7 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_CB_2147934238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CB!MTB"
        threat_id = "2147934238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 d2 f7 35 ?? ?? ?? ?? 8b 45 14 8b 40 04 0f b6 04 10 50 8b 45}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 09 0f b6 04 01 50 e8 ?? ?? ?? ff 59 59 50 8d 4d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CC_2147934239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CC!MTB"
        threat_id = "2147934239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nKHdNVTTMKtmDhwssaDYbQJhwmmhZM" ascii //weight: 1
        $x_1_2 = "wmSFGGHugLjGVuEtRLRDCIxpCOsWDQ" ascii //weight: 1
        $x_1_3 = "JmDVrofBCcCRtRyHEjBrtTPBvzNMcodWEM" ascii //weight: 1
        $x_1_4 = "IkqJuFOGZyWYPezTRyBRplnYJ" ascii //weight: 1
        $x_1_5 = "zgYgDCsVHEQmGmkmNjzsLUnMbZGs" ascii //weight: 1
        $x_1_6 = "QvyjBQxcSdLYoPIqzfsAgwUIfGICkGjfbZ" ascii //weight: 1
        $x_1_7 = "euJsrLWUwqxGqaMezPuindOfEBNjA" ascii //weight: 1
        $x_1_8 = "lxgkeUmKOrXfUKPOOwIPlSZtdKoUMovy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFM_2147934477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFM!MTB"
        threat_id = "2147934477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 a0 40 89 45 a0 83 7d a0 00 7f 11 8b 45 a0}  //weight: 2, accuracy: High
        $x_1_2 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 40 6a 04 59 6b c9 00 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 00}  //weight: 1, accuracy: Low
        $x_1_3 = {eb 07 8b 45 cc 40 89 45 cc 83 7d cc 01 7d 10 8b 45 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CD_2147934693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CD!MTB"
        threat_id = "2147934693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 f1 0f af 45 f8 89 45 f4 69 4d f4 ?? 00 00 00 69 45 f4 ?? 00 00 00 2b c8 03 4d ?? ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 fc 03 45 ?? 59 59 3b f0 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CE_2147935040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CE!MTB"
        threat_id = "2147935040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 f1 0f af 45 f8 89 45 f8 69 4d f8 ?? 00 00 00 69 45 f8 ?? 00 00 00 2b c8 8b 45 08 03 4d f4 ff 34 88 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72}  //weight: 5, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec ?? 8b 45 08 03 45 0c}  //weight: 1, accuracy: Low
        $x_4_3 = {6a 1d 59 33 d2 8b c6 f7 f1 ff 34 97 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f8 03 45 f0 59 59 3b f0 72}  //weight: 4, accuracy: Low
        $x_4_4 = {8b c6 83 e0 3f ff 34 87 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 f8 03 45 fc 59 59 3b f0 72}  //weight: 4, accuracy: Low
        $x_4_5 = {2b c8 8b 45 08 2b 4d fc ff 34 88 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 59 59 3b f7 72}  //weight: 4, accuracy: Low
        $x_1_6 = {8b 4d fc 8b 45 f8 f7 f1 89 45 fc 8b 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_NMA_2147935139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMA!MTB"
        threat_id = "2147935139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 15 6a 04 58 6b c0 00 8b 44 05 f0 48 6a 04 59 6b c9 00 89 44 0d f0 6a 04 58 6b c0 00}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec 02 7d 0d 8b 45 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMB_2147935146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMB!MTB"
        threat_id = "2147935146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 13 6a 04 58 d1 e0 8b 44 05 84 40 6a 04 59 d1 e1 89 44 0d 84 6a 04 58 d1 e0}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 f4 40 89 45 f4 83 7d f4 01 7d 0d 8b 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMC_2147935237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMC!MTB"
        threat_id = "2147935237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 40 c1 e0 00 0f b6 84 05 ?? ff ff ff 83 c8 2f 33 c9 41 c1 e1 00 0f b6 8c 0d ?? ff ff ff 83 e1 2f 2b c1 33 c9 41 6b c9 00}  //weight: 2, accuracy: Low
        $x_1_2 = {eb 08 8b 45 e4 40 40 89 45 e4 83 7d e4 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMD_2147935752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMD!MTB"
        threat_id = "2147935752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 1f 0f b6 c8 8b d1 88 85 53 fe ff ff c1 ea 03 83 e1 07 b0 01 d2 e0 08 44 15 dc 8a 95 53 fe ff ff 8a 07 3c 5d}  //weight: 2, accuracy: High
        $x_1_2 = {99 2b c2 8b c8 d1 f9 8b 85 ?? ?? ff ff 40 0f af 85 ?? ?? ff ff 99 2b c2 d1 f8 03 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NME_2147935792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NME!MTB"
        threat_id = "2147935792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ?? ff ff 8d 44 00 02 39 45 dc}  //weight: 1, accuracy: Low
        $x_2_2 = {7d 70 83 65 9c 00 eb 07 8b 45 9c 40 89 45 9c 81 7d 9c}  //weight: 2, accuracy: High
        $x_2_3 = {eb 07 8b 45 8c 40 89 45 8c 83 7d 8c 03 7d 10 8b 45 8c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMF_2147935878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMF!MTB"
        threat_id = "2147935878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 40 c1 e0 00 0f b6 84 05 ?? ff ff ff 83 c8 39 33 c9 41 c1 e1 00 0f b6 8c 0d ?? ff ff ff 83 e1 39 2b c1 33 c9 41 6b c9 00}  //weight: 1, accuracy: Low
        $x_2_2 = {eb 07 8b 45 d0 40 89 45 d0 83 7d d0 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMG_2147935909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMG!MTB"
        threat_id = "2147935909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 9c 40 89 45 9c 83 7d 9c 03 7d 10 8b 45 9c}  //weight: 1, accuracy: High
        $x_2_2 = {eb 04 83 4d fc ff 6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 00}  //weight: 2, accuracy: Low
        $x_1_3 = {eb 07 8b 45 94 40 89 45 94 83 7d 94 01 7d 10 8b 45 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMI_2147936246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMI!MTB"
        threat_id = "2147936246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 e8 40 89 45 e8 83 7d e8 03}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 6a 04 59 6b c9 03}  //weight: 2, accuracy: Low
        $x_1_3 = {eb 1b 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 03 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMK_2147936247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMK!MTB"
        threat_id = "2147936247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 4d fc ff eb 04 83 4d fc ff 6a 04 58 6b c0 00}  //weight: 1, accuracy: High
        $x_2_2 = {ff 99 f7 bd ?? ?? ff ff 8b c2 99 f7 bd ?? ?? ff ff 8b c2 99}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMK_2147936247_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMK!MTB"
        threat_id = "2147936247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {79 05 48 83 c8 fe 40 85 c0 74 09}  //weight: 1, accuracy: High
        $x_2_2 = {6a 05 59 f7 f9 03 85 ?? ?? ff ff 99 8b f0 8b fa}  //weight: 2, accuracy: Low
        $x_1_3 = {8b f0 6a 05 58 2b 85 ?? ?? ff ff 99 6a 05 59 f7 f9 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NML_2147936692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NML!MTB"
        threat_id = "2147936692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 0d 8b 85 ?? ?? ff ff 40 89}  //weight: 1, accuracy: Low
        $x_2_2 = {8b 00 40 8b 8d ?? ?? ff ff 89 01 8b 85 ?? ?? ff ff 40 50 8d 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMP_2147936712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMP!MTB"
        threat_id = "2147936712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 03 7d 0d 8b 45 dc}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 d1 e0 8b 44 05 80 89 85 ?? ?? ff ff 6a 04 58 d1 e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMR_2147937568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMR!MTB"
        threat_id = "2147937568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 01 7d 0d 8b 45 dc}  //weight: 1, accuracy: High
        $x_2_2 = {eb 07 83 a5 68 fd ff ff 00 6a 04 58 6b c0 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMS_2147937731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMS!MTB"
        threat_id = "2147937731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 d8 40 89 45 d8 83 7d d8 03 7d 10 8b 45 d8}  //weight: 1, accuracy: High
        $x_1_2 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 00}  //weight: 1, accuracy: Low
        $x_2_3 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ?? ff ff 8d 44 00 02 39 45 d0 75 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMT_2147937815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMT!MTB"
        threat_id = "2147937815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 88 40 89 45 88 83 7d 88 26}  //weight: 1, accuracy: High
        $x_2_2 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ?? ff ff 8d 44 00 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CF_2147938129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CF!MTB"
        threat_id = "2147938129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b c8 2b 4d ?? ?? 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 ?? 03 45 ?? 59 59 3b f0 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CG_2147938228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CG!MTB"
        threat_id = "2147938228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 23 45 0c 89 85 ?? ?? ff ff 8b 45 08 23 45 0c 89 85}  //weight: 2, accuracy: Low
        $x_1_2 = {2b c8 03 4d}  //weight: 1, accuracy: High
        $x_1_3 = {ff ff 2b 85}  //weight: 1, accuracy: High
        $x_1_4 = {ff ff 89 85}  //weight: 1, accuracy: High
        $x_1_5 = {ff ff 8b 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMV_2147938364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMV!MTB"
        threat_id = "2147938364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 bc 40 89 45 bc 83 7d bc 02 7d 10 8b 45 bc}  //weight: 1, accuracy: High
        $x_2_2 = {eb 07 83 a5 ?? ?? ff ff 00 6a 04 58 c1 e0 00 83 bc 05 ?? ?? ff ff 00 74 1c 6a 04 58 6b c0 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMW_2147938451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMW!MTB"
        threat_id = "2147938451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7c b4 8b 7c 24 10 8b 74 24 14 47 89 7c 24 10}  //weight: 1, accuracy: High
        $x_1_2 = {7e 05 83 fe ff 75 07 8b 7d fc 4b 89 75 fc 85 db 79 d0 8b 45 14 46}  //weight: 1, accuracy: High
        $x_2_3 = {55 8b ec 8b 45 08 56 8b f1 83 66 04 00 c7 06 ?? ?? ?? ?? c6 46 08 00 ff 30}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CH_2147938937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CH!MTB"
        threat_id = "2147938937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 f1 0f af 45}  //weight: 2, accuracy: High
        $x_3_2 = {ff 34 88 ff 34 b3 e8 ?? ?? ff ff 89 04 b3}  //weight: 3, accuracy: Low
        $x_3_3 = {ff 34 8b ff 34 b8 e8 ?? ?? ff ff 59 59 8b 4d ?? 89 04 b9 47}  //weight: 3, accuracy: Low
        $x_3_4 = {ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45}  //weight: 3, accuracy: Low
        $x_3_5 = {ff 34 8f ff 34 b3 e8 ?? ?? ff ff 89 04 b3}  //weight: 3, accuracy: Low
        $x_3_6 = {ff 34 8b ff 34 b7 e8 ?? ?? ff ff 89 04 b7}  //weight: 3, accuracy: Low
        $x_2_7 = {59 59 3b f0 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Neoreblamy_NMZ_2147939341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMZ!MTB"
        threat_id = "2147939341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 01 7d 0d 8b 45 fc}  //weight: 1, accuracy: High
        $x_2_2 = {eb e3 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NMY_2147939670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NMY!MTB"
        threat_id = "2147939670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 f0 40 89 45 f0 83 7d f0 03 7f 11 8b 45 f0}  //weight: 1, accuracy: High
        $x_2_2 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 40 6a 04 59 6b c9 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CI_2147940579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CI!MTB"
        threat_id = "2147940579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b c8 8b 45 f4 2b 4d f8 ff 34 8f ff 34 b0 e8 ?? ?? ?? ff 59 59 8b 4d f4 89 04 b1 46 8b 45 f0 03 c3}  //weight: 5, accuracy: Low
        $x_5_2 = {2b c8 03 4d fc ff 34 8b ff 34 b7 e8 ?? ?? ?? ff 89 04 b7 46 8b 45 f4 03 45 f0 59 59 3b f0 0f 82}  //weight: 5, accuracy: Low
        $x_5_3 = {ff 34 8b ff 34 b8 e8 ?? ?? ?? ff 59 59 8b 4d f4 89 04 b9 47 8b 45 f0 03 c6 3b f8 0f 82}  //weight: 5, accuracy: Low
        $x_5_4 = {2b c8 2b 4d f8 ff 34 8f ff 34 b3 e8 ?? ?? ?? ff 89 04 b3 46 8b 45 f4 03 45 ec 59 59 3b f0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFZ_2147940581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFZ!MTB"
        threat_id = "2147940581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 0c ff ff ff 40 6a 04 59 6b c9 00}  //weight: 1, accuracy: High
        $x_1_2 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 01 7d 10}  //weight: 1, accuracy: High
        $x_2_3 = {6a 04 5a 6b d2 00 8b 94 15 ?? ?? ff ff 4a 6a 04 5e 6b f6 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFX_2147940665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFX!MTB"
        threat_id = "2147940665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 83 a5 60 fe ff ff 00 6a 04 58 d1 e0}  //weight: 1, accuracy: High
        $x_1_2 = {eb 07 8b 45 f4 40 89 45 f4 83 7d f4 04 7d 10 8b 45 f4}  //weight: 1, accuracy: High
        $x_2_3 = {1b 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 40 6a 04 59 6b c9 03 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFW_2147940868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFW!MTB"
        threat_id = "2147940868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 d8 40 89 45 d8 83 7d d8 01 7d 10 8b 45 d8}  //weight: 1, accuracy: High
        $x_1_2 = {48 6a 04 59 6b c9 00 89 84 0d 30 ff ff ff 6a 04 58 6b c0 00}  //weight: 1, accuracy: High
        $x_2_3 = {eb 1b 6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 c1 e1 00 89 84 0d ?? ?? ff ff 6a 04 58 c1 e0 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFV_2147940978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFV!MTB"
        threat_id = "2147940978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 98 40 89 45 98 83 7d 98 02 7d 10 8b 45 98}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 59 d1 e1 8b 8c 0d ?? ?? ff ff 41 6a 04 5a d1 e2}  //weight: 2, accuracy: Low
        $x_1_3 = {eb 07 83 a5 28 fe ff ff 00 6a 04 58 d1 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CJ_2147940997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CJ!MTB"
        threat_id = "2147940997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 4d f8 ff 34 8b ff 34 b7 e8 ?? ?? ff ff 89 04 b7 46 8b 45}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 55 ec 59 59 8b 4d fc 89 04 8a 41 8b 45 f8 03 c7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFU_2147941182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFU!MTB"
        threat_id = "2147941182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 f8 40 89 45 f8 83 7d f8 01 7d 10 8b 45 f8}  //weight: 1, accuracy: High
        $x_2_2 = {eb 1b 6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 c1 e1 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFT_2147941542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFT!MTB"
        threat_id = "2147941542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 04 7d 10 8b 45 dc}  //weight: 1, accuracy: High
        $x_2_2 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ?? ff ff 8d 44 00 02 39 45 b4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_CK_2147941563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.CK!MTB"
        threat_id = "2147941563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 55 f4 6b 4d f4}  //weight: 1, accuracy: High
        $x_1_2 = {2b c8 03 4d e0}  //weight: 1, accuracy: High
        $x_1_3 = {2b f8 8b 45}  //weight: 1, accuracy: High
        $x_1_4 = {ff ff 59 59 8b 4d}  //weight: 1, accuracy: High
        $x_1_5 = {2b c8 03 4d e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFS_2147941752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFS!MTB"
        threat_id = "2147941752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 01 7d 10 8b 45 c0}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 6a 04 59 6b c9 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_HB_2147941867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.HB!MTB"
        threat_id = "2147941867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 [0-6] 63 00 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 22 10 10 03 61 2d 7a 5c 00 22 07 07 03 61 2d 7a 2e 00 77 00 73 00 66 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFR_2147941906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFR!MTB"
        threat_id = "2147941906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 58 d1 e0 8b 84 05 ?? ff ff ff 6a 04 59 6b c9 00}  //weight: 1, accuracy: Low
        $x_2_2 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 ?? 7d 10 8b 45 c0}  //weight: 2, accuracy: Low
        $x_1_3 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 48 89 85 ?? ?? ff ff 6a 04 58 6b c0 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFQ_2147942011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFQ!MTB"
        threat_id = "2147942011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 40 c1 e0 00 0f b6 84 05 ?? ?? ff ff 0d ef 00 00 00 33 c9 41 c1 e1 00 0f b6 8c 0d ?? ?? ff ff 81 e1 ef 00 00 00 2b c1 33 c9 41 6b c9 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFO_2147942121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFO!MTB"
        threat_id = "2147942121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 04 58 6b c0 00 8b 84 05 24 fe ff ff 40 6a 04 59 6b c9 00 89 84 0d 24 fe ff ff 6a 04 58 6b c0 00}  //weight: 2, accuracy: High
        $x_1_2 = {eb 07 8b 45 f0 48 89 45 f0 83 7d f0 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFJ_2147942379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFJ!MTB"
        threat_id = "2147942379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 c4 40 89 45 c4 83 7d c4 ?? 7d 0d 8b 45 c4}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 c1 e1 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NFI_2147942565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NFI!MTB"
        threat_id = "2147942565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 c1 e0 00}  //weight: 2, accuracy: Low
        $x_1_2 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec ?? 7d 10 8b 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJZ_2147942623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJZ!MTB"
        threat_id = "2147942623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 03 7d 10 8b 45 fc}  //weight: 2, accuracy: High
        $x_1_2 = {6a 04 58 d1 e0 8b 84 05 ?? ff ff ff 40 6a 04 59 d1 e1 89 84 0d ?? ff ff ff 6a 04 58 d1 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJY_2147942721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJY!MTB"
        threat_id = "2147942721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 07 8b 45 e4 40 89 45 e4 83 7d e4 04 7d 0d 8b 45 e4}  //weight: 2, accuracy: High
        $x_1_2 = {74 12 8b f3 8b cb c1 fe 03 83 e1 07 b2 01 d2 e2 08 54 3e 0c 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJX_2147942835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJX!MTB"
        threat_id = "2147942835"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 dc 40 89 45 dc 83 7d dc 01 7d 0d 8b 45 dc}  //weight: 2, accuracy: High
        $x_1_2 = {6a 04 58 c1 e0 00 83 bc 05 ?? ff ff ff 00 75 16 6a 04 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJW_2147942925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJW!MTB"
        threat_id = "2147942925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 f4 40 89 45 f4 83 7d f4 02 7d 0d 8b 45 f4}  //weight: 2, accuracy: High
        $x_1_2 = {8b 45 ec 8b 4d e8 83 c0 ff 89 45 ec 83 d1 ff 89 4d e8 e9 ?? ff ff ff 8b 45 ec 8b 4d e8 83 c0 ff 89 45 ec 83 d1 ff 89 4d e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_PGN_2147943229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.PGN!MTB"
        threat_id = "2147943229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 ff 83 65 ?? ?? 8b de 8b 75 ?? 8b cf d3 e3 8b c3 33 c6 99 52 50 ?? ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 7c ?? 8b 75 ?? 47 81 ff ?? ?? ?? ?? 7c ?? 46 89 75 ?? 81 fe ?? ?? ?? ?? 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_PGNE_2147943230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.PGNE!MTB"
        threat_id = "2147943230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 c7 84 85 ?? ?? ?? ?? ?? ?? ?? ?? ff 45 f8 39 4d f8 7c ea}  //weight: 1, accuracy: Low
        $x_4_2 = {f7 d8 1b c0 40 2b 45 ?? f7 d8 1b c0 40}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJV_2147943290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJV!MTB"
        threat_id = "2147943290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59}  //weight: 2, accuracy: Low
        $x_1_2 = {eb 08 8b 45 f0 40 40 89 45 f0 83 7d f0 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJV_2147943290_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJV!MTB"
        threat_id = "2147943290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 58 6b c0 00 8b 84 05 b4 fe ff ff 40 6a 04 59 6b c9 00}  //weight: 1, accuracy: High
        $x_2_2 = {eb 07 8b 45 b8 40 89 45 b8 83 7d b8 03 7d 10 8b 45 b8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJU_2147943447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJU!MTB"
        threat_id = "2147943447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {eb 07 8b 45 d4 40 89 45 d4 83 7d d4 01 7d 10 8b 45 d4}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_HA_2147943523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.HA!MTB"
        threat_id = "2147943523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "forfiles" wide //weight: 1
        $x_5_2 = "wscript.exe /c cmd /C @FNAME" wide //weight: 5
        $x_10_3 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 [0-56] 2e 00 77 00 73 00 66 00 5e 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJT_2147943649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJT!MTB"
        threat_id = "2147943649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 8b 45 f4 40 89 45 f4 83 7d f4 01 7d 0d 8b 45 f4}  //weight: 1, accuracy: High
        $x_2_2 = {eb 07 8b 45 f8 48 89 45 f8 83 7d f8 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJS_2147943768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJS!MTB"
        threat_id = "2147943768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 94 40 89 45 94 83 7d 94 03 7d 10 8b 45 94}  //weight: 1, accuracy: High
        $x_2_2 = {33 c0 40 6b c0 00 0f b6 84 05 ?? ff ff ff 8d 44 00 02 39 45 d8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJR_2147943884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJR!MTB"
        threat_id = "2147943884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 a0 40 89 45 a0 83 7d a0 04 7d 10 8b 45 a0}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 39 45 f0 75 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJQ_2147943998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJQ!MTB"
        threat_id = "2147943998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 c4 40 89 45 c4 83 7d c4 03 7d 10 8b 45 c4}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 40 6a 04 59 c1 e1 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJP_2147944185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJP!MTB"
        threat_id = "2147944185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 a8 40 89 45 a8 83 7d a8 01 7d 0d 8b 45 a8}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 6b c0 00 8b 8d ?? ?? ff ff 89 4c 05 dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJO_2147944273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJO!MTB"
        threat_id = "2147944273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 80 40 89 45 80 83 7d 80 02 7d 10 8b 45 80}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 40 6a 04 59 6b c9 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJN_2147944381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJN!MTB"
        threat_id = "2147944381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 90 40 89 45 90 83 7d 90 01 7d 10 8b 45 90}  //weight: 1, accuracy: High
        $x_2_2 = {eb 1b 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 03 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJM_2147944518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJM!MTB"
        threat_id = "2147944518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 07 8b 45 9c 40 89 45 9c 83 7d 9c 02}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 6b c0 00 83 bc 05 d8 fe ff ff 00 74 1c 6a 04 58 6b c0 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJL_2147944619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJL!MTB"
        threat_id = "2147944619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 f4 48 89 45 f4 83 7d f4 ff}  //weight: 1, accuracy: High
        $x_2_2 = {7c c9 46 81 fe ?? ?? 00 00 7c be 81 7c 24 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJK_2147944716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJK!MTB"
        threat_id = "2147944716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 01 7d 0d 8b 45 fc}  //weight: 1, accuracy: High
        $x_2_2 = {8d 45 94 50 33 d2 42 33 c9 e8 ?? ?? ff ff 59 59}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJI_2147944866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJI!MTB"
        threat_id = "2147944866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 08 8b 45 d4 40 40 89 45 d4 83 7d d4}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 d1 e0 8b 84 05 ?? ?? ff ff 40 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NLP_2147945182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NLP!MTB"
        threat_id = "2147945182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 07 8b 45 9c 40 89 45 9c 83 7d 9c 02 7d 10 8b 45}  //weight: 2, accuracy: High
        $x_1_2 = {6a 04 58 c1 e0 00 8b 84 05 ?? ?? ?? ff 6a 04 59 6b c9 00}  //weight: 1, accuracy: Low
        $x_1_3 = {19 6a 04 58 d1 e0 8b 84 05 ?? ?? ?? ff 48 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJH_2147945183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJH!MTB"
        threat_id = "2147945183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 80 40 89 45 80 83 7d 80 04 7d 10 8b 45 80}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 6b c0 00 8b 44 05 b0 89 85 ?? ?? ff ff 6a 04 58 c1 e0 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_PGNL_2147945222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.PGNL!MTB"
        threat_id = "2147945222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 85 48 ff ff ff 40 89 85 48 ff ff ff 83 bd 48 ff ff ff ?? 7d ?? 8b 85 48 ff ff ff c7 84 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJG_2147945292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJG!MTB"
        threat_id = "2147945292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 88 40 89 45 88 83 7d 88 02 7d 10 8b 45 88}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 89 85 ?? ?? ff ff 6a 04 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJF_2147945499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJF!MTB"
        threat_id = "2147945499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 8b 55 e8 83 c2 01 89 55 e8 8b 45 e8 3b 45 e0}  //weight: 1, accuracy: High
        $x_2_2 = {eb 0d 8b 45 f0 89 8c 85 ?? ?? ff ff ff 45 f0 39 7d f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJE_2147945545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJE!MTB"
        threat_id = "2147945545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 07 8b 45 f8 40 89 45 f8 83 7d f8 02 7d 0d 8b 45 f8}  //weight: 1, accuracy: High
        $x_2_2 = {07 8b 45 fc 40 89 45 fc 83 7d fc 04 7d 0d 8b 45 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJD_2147945606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJD!MTB"
        threat_id = "2147945606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 c8 40 89 45 c8 83 7d c8 02 7d 10 8b 45 c8}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 d1 e0 8b 84 05 ?? ?? ff ff 48 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJC_2147945742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJC!MTB"
        threat_id = "2147945742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 ?? 7d 10 8b 45 c0}  //weight: 1, accuracy: Low
        $x_2_2 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 89 45 d4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJB_2147946010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJB!MTB"
        threat_id = "2147946010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 a8 40 89 45 a8 83 7d a8 02 7d 0d 8b 45 a8}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 6b c0 00 8b 44 05 b0 89 85 ?? ?? ff ff 6a 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NJA_2147946138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NJA!MTB"
        threat_id = "2147946138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec ?? 7d 10 8b 45 ec}  //weight: 1, accuracy: Low
        $x_2_2 = {6a 04 58 6b c0 00 8b 84 05 ?? ff ff ff 3b 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NIA_2147946341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NIA!MTB"
        threat_id = "2147946341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 a4 40 89 45 a4 83 7d a4 ?? 7d 10 8b 45 a4}  //weight: 1, accuracy: Low
        $x_2_2 = {6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Neoreblamy_NIB_2147946583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.NIB!MTB"
        threat_id = "2147946583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 07 8b 45 c4 48 89 45 c4 83 7d c4 00}  //weight: 1, accuracy: High
        $x_2_2 = {6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 c1 e1 00 89 84 0d ?? ?? ff ff 6a 04 58 c1 e0 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

