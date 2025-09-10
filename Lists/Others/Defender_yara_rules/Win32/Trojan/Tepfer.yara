rule Trojan_Win32_Tepfer_RJ_2147775937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.RJ!MTB"
        threat_id = "2147775937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 4c 24 ?? 33 cb 33 ce}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_RB_2147836465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.RB!MTB"
        threat_id = "2147836465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 2c 00 00 00 c7 45 dc 7b 7d 6b 7c c7 45 e0 7e 7c 61 68 c7 45 e4 67 62 6b 2e 8b 38}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 e0 6d 6d 42 4b c7 45 e4 4f 40 4b 5c c6 45 bf 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_PAB_2147845160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.PAB!MTB"
        threat_id = "2147845160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 4c 24 20 89 4c 24 10 8d 0c 07 c1 e8 05 89 44 24 14 8b 44 24 24 01 44 24 14 8b 44 24 10 33 c1 31 44 24 14 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10 89 1d cc 22 7f 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_NT_2147901181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.NT!MTB"
        threat_id = "2147901181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 5d e7 ff 75 ?? e8 1d fe ff ff 59 e8 0d 07 00 00 8b f0 33 ff 39 3e 74 1b 56 e8 75 fd ff ff 59 84 c0}  //weight: 5, accuracy: Low
        $x_1_2 = "AppPolicyGetProcessTerminationMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_SPDB_2147907967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.SPDB!MTB"
        threat_id = "2147907967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 33 83 ff 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_FK_2147911072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.FK!MTB"
        threat_id = "2147911072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 04 8b 85 ?? ?? ff ff 83 c0 64 89 85 ?? ?? ff ff 83 ad ?? ?? ff ff 64 8a 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 30 14 30 83 7d ?? 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_SPPB_2147913143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.SPPB!MTB"
        threat_id = "2147913143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c7 33 c2 33 45 74 c7 05 ?? ?? ?? ?? ee 3d ea f4 2b c8 89 45 70 8b c1 c1 e0 04 89 45 74 8b 85 ?? ?? ?? ?? 01 45 74 8b c1 c1 e8 05 89 45 70 8b 85 ?? ?? ?? ?? 01 45 70 8d 04 0e 33 45 70 31 45 74 8b 45 74 29 45 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_GNN_2147919098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.GNN!MTB"
        threat_id = "2147919098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 08 8a 4d fc 03 c7 30 08 47 3b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_EM_2147926886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.EM!MTB"
        threat_id = "2147926886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {31 3e 83 c3 04 83 c6 04 3b 5d e0 72 b1 b8 00 10 00 00 8b 55 e4 03 55 dc 2b d0 83 c2 04 89 55 ec}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_EM_2147926886_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.EM!MTB"
        threat_id = "2147926886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aPmC12HFdIFY6yGJ-EnH/dvaKDi5ctyNIOUcEbYSI/X-6_aGGcoVUvfg3yINiE/147N6D7NvERkkLhbMxtu" ascii //weight: 1
        $x_1_2 = "mickep76/encdec" ascii //weight: 1
        $x_1_3 = "rasky/go-lzo" ascii //weight: 1
        $x_1_4 = "chrispassas/silk@v1.3.0/file.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_SPCI_2147929650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.SPCI!MTB"
        threat_id = "2147929650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e8 05 89 45 fc 8b 45 f8 8b 55 e8 01 55 fc 03 c7 33 f0 81 3d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_SPXC_2147931544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.SPXC!MTB"
        threat_id = "2147931544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vculuxuhil fanosah wakonafobovecizinabefuc" wide //weight: 2
        $x_2_2 = "vifolujimik vubomutadacatoxewesikiciyekofuvi wiwuve" wide //weight: 2
        $x_2_3 = "faronicopixubefigucuvefurolik bojigake kuradomayihavabica zol jurogi" wide //weight: 2
        $x_1_4 = "fetujowuwovacahuyamegeday dinocizifucevujabataco kafaxopipesamaniyukiza" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_ATP_2147936485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.ATP!MTB"
        threat_id = "2147936485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 fc 56 5f 33 39 83 ef 01 89 3b ff 33 6a fc 5e ?? ?? 2b ce 2b de 5e 0f ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_BA_2147937162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.BA!MTB"
        threat_id = "2147937162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 c7 31 03 83 45 ec 04 83 c3 04 8b 45 ec 3b 45 dc 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_EAHR_2147938594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.EAHR!MTB"
        threat_id = "2147938594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 03 8b 8d 00 ef ff ff 8a 5c 08 03 88 9d 04 ef ff ff c0 e3 02 81 3d ?? ?? ?? ?? 09 0d 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_BAB_2147938610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.BAB!MTB"
        threat_id = "2147938610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c0 8b 55 ec 01 13 8b 75 d4 03 75 ac 03 75 ec 03 f0 bf 89 15 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_PGT_2147938920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.PGT!MTB"
        threat_id = "2147938920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c8 c1 e9 1e 33 c8 69 c1 ?? ?? ?? ?? 03 c6 89 84 b5 74 ec ff ff 46 3b f2 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_SGGL_2147939669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.SGGL!MTB"
        threat_id = "2147939669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 33 c9 89 5d f8 8b c6 8b 7e 10 47 83 7e 14 10 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_BAC_2147941283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.BAC!MTB"
        threat_id = "2147941283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5a 2b d0 31 13 6a 00 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_BAC_2147941283_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.BAC!MTB"
        threat_id = "2147941283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5a 2b d0 31 13 83 45 ec 04 6a 00 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_BAD_2147943151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.BAD!MTB"
        threat_id = "2147943151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b f8 8b 45 dc 31 38 83 45 ec 04 83 45 dc 04 8b 45 ec 3b 45 d8 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_BAD_2147943151_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.BAD!MTB"
        threat_id = "2147943151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 00 10 00 00 8b 55 ?? 03 55 ?? 2b d0 83 c2 04 89 55 ?? b8 6a 0a 00 00 ff 75 ?? b8 6a 0a 00 00 ff 75 ?? b8 6a 0a 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_MR_2147949736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.MR!MTB"
        threat_id = "2147949736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d e0 72}  //weight: 10, accuracy: Low
        $x_5_2 = {01 1e 8b 7d d8 03 7d a4 03 fb 03 f8 c7 45 b8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_BAF_2147951954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.BAF!MTB"
        threat_id = "2147951954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c3 8a 00 f3 0f 10 e4 f3 0f 10 ed 90 90 34 56 8b 15 ?? ?? ?? ?? 03 d3 88 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tepfer_BAG_2147951955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tepfer.BAG!MTB"
        threat_id = "2147951955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tepfer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 00 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 83 c4 08 5a 88 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

