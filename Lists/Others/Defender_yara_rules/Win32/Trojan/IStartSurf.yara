rule Trojan_Win32_IStartSurf_DSK_2147742755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.DSK!MTB"
        threat_id = "2147742755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0c 06 8b c6 f7 75 d0 8b 45 14 88 4d ff 8a 04 02 32 c1 8b 4d 10 88 04 0e}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 dc 83 c0 12 50 ff 75 d4 8b 45 dc ff 70 04 8b 45 dc 8b 4d d8 03 08 51 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IStartSurf_VDSK_2147743754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.VDSK!MTB"
        threat_id = "2147743754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 88 4d 0f 8a 04 02 32 c1 8b 4d 18 88 04 0e 8b 45 bc}  //weight: 2, accuracy: High
        $x_2_2 = {89 45 e8 89 7d f8 03 c0 83 f1 3a 8b 45 cc 40 89 7d d4 89 45 cc 3b 45 10 0f 82}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IStartSurf_PVD_2147746162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.PVD!MTB"
        threat_id = "2147746162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 8a 04 02 8b 55 20 32 04 11 8b 55 18 88 04 11 8b 45 b4 89 45 bc}  //weight: 2, accuracy: High
        $x_2_2 = {8a 0c 02 8b 45 20 8a 04 06 32 c1 8b 4d 18 88 04 0e 8b 45 b4 89 45 d4 8b 45 cc 89 45 ec}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IStartSurf_MG_2147749156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.MG!MTB"
        threat_id = "2147749156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 89 04 8a 41 81 f9 ?? ?? ?? ?? 7c 11 00 8b 44 8a ?? c1 e8 ?? 33 44 8a ?? 69 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {33 0c ba 81 e1 ?? ?? ?? ?? 33 0c ba 8b c1 d1 e9 83 e0 ?? 69 c0 ?? ?? ?? ?? 33 c1 33 84 ba ?? ?? ?? ?? 89 04 ba 47 3b fe 7c 04 00 8b 4c ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IStartSurf_PVS_2147749238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.PVS!MTB"
        threat_id = "2147749238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 5d 9c 83 c3 01 f7 f3 89 45 b4 68 ?? ?? ?? ?? 5a 0b d0 c1 e2 0a 89 55 cc}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 cc 48 89 45 cc 8b 45 b4 83 c8 0c 39 45 cc 0f 87}  //weight: 2, accuracy: High
        $x_2_3 = {8b 40 36 8b 4d d8 8b 04 01 89 45 e0 8b 45 e0 33 d2 b9 00 00 01 00 f7 f1 8b 45 e0 2b c2 89 45 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_PVK_2147750104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.PVK!MTB"
        threat_id = "2147750104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 9d 74 ff ff ff 83 c3 01 f7 f3 89 45 9c 68 ?? ?? ?? ?? 5a 0b d0 c1 e2 0a 89 55 bc}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 bc 48 89 45 bc 8b 45 9c 83 c8 0c 39 45 bc 0f 87}  //weight: 2, accuracy: High
        $x_2_3 = {8b 40 36 8b 4d d8 8b 04 01 89 45 e0 8b 45 e0 33 d2 b9 00 00 01 00 f7 f1 8b 45 e0 2b c2 89 45 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_PDSK_2147750139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.PDSK!MTB"
        threat_id = "2147750139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 4d ff 8a 04 02 32 c1 8b 4d 10 88 04 0e 8b 45 0c 89 45 e4 8b 45 c8 89 45 f4 83 ca 76}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_KVP_2147750527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.KVP!MTB"
        threat_id = "2147750527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 9d 70 ff ff ff 83 c3 01 f7 f3 89 45 98 68 ?? ?? ?? ?? 5a 0b d0 c1 e2 0a 89 55 b8}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 b8 48 89 45 b8 8b 45 98 83 c8 0c 39 45 b8 0f 87}  //weight: 2, accuracy: High
        $x_2_3 = {8b 40 36 8b 4d d8 8b 04 01 89 45 e0 8b 45 e0 33 d2 b9 00 00 01 00 f7 f1 8b 45 e0 2b c2 89 45 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_KDS_2147750848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.KDS!MTB"
        threat_id = "2147750848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 9d 6c ff ff ff 83 c3 01 f7 f3 89 45 94 68 ?? ?? ?? ?? 5a 0b d0 c1 e2 0a 89 55 b8}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 9d 70 ff ff ff 83 c3 01 f7 f3 89 45 98 68 ?? ?? ?? ?? 5a 0b d0 c1 e2 0a 89 55 b8}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 45 b8 48 89 45 b8 8b 45 ?? 83 c8 0c 39 45 b8 0f 87}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 40 36 8b 4d d8 8b 04 01 89 45 e0 8b 45 e0 33 d2 b9 00 00 01 00 f7 f1 8b 45 e0 2b c2 89 45 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_IStartSurf_VSD_2147751448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.VSD!MTB"
        threat_id = "2147751448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 9d 6c ff ff ff 83 c3 01 f7 f3 89 45 94 68 ?? ?? ?? ?? 5a 0b d0 c1 e2 0a 89 55 b8}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 b4 48 89 45 b4 8b 45 ?? 83 c8 0c 39 45 b4 0f 87}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 40 36 8b 4d d8 8b 04 01 89 45 e0 8b 45 e0 33 d2 b9 00 00 01 00 f7 f1 8b 45 e0 2b c2 89 45 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_VDP_2147751745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.VDP!MTB"
        threat_id = "2147751745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 9d 58 ff ff ff 83 c3 01 f7 f3 89 45 8c 68 ?? ?? ?? ?? 5a 0b d0 c1 e2 0a 89 55 b8}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 b8 48 89 45 b8 8b 45 ?? 83 c8 0c 39 45 b8 0f 87}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 40 36 8b 4d ?? 8b 04 01 89 45 e0 8b 45 e0 33 d2 b9 00 00 01 00 f7 f1 8b 45 e0 2b c2 89 45 e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_GM_2147752342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.GM!MTB"
        threat_id = "2147752342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 dc 8b 4d cc 3b 48 04 0f 83 [0-32] 03 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 94 03 45 cc 8a 00 88 45 d7 [0-48] 0f af}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c8 8b 45 c8 03 45 cc 88 08 [0-48] 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_PDK_2147752584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.PDK!MTB"
        threat_id = "2147752584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d e0 c1 e9 05 03 4d b4 33 c1 8b 55 e4 2b d0 89 55 e4 8b 45 c8 2b 45 b0 89 45 c8 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_DSP_2147752813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.DSP!MTB"
        threat_id = "2147752813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 9d 60 ff ff ff 83 c3 01 f7 f3 89 45 94 68 ?? ?? ?? ?? 5a 0b d0 c1 e2 0a 89 55 bc}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 bc 48 89 45 bc 8b 45 ?? 83 c8 0c 39 45 bc 0f 87}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 40 36 8b 4d d8 8b 04 01 89 45 e0 8b 45 e0 33 d2 b9 00 00 01 00 f7 f1 8b 45 e0 2b c2 89 45 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_PVE_2147753884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.PVE!MTB"
        threat_id = "2147753884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 9d 60 ff ff ff 83 c3 01 f7 f3 89 45 94 68 ?? ?? ?? ?? 5a 0b d0 c1 e2 0a 89 55 bc}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 bc 48 89 45 bc 8b 45 94 83 c8 0c 39 45 bc 0f 87}  //weight: 2, accuracy: High
        $x_2_3 = {8b 40 36 8b 4d d8 8b 04 01 89 45 e0 8b 45 e0 33 d2 b9 00 00 01 00 f7 f1 8b 45 e0 2b c2 89 45 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_IStartSurf_PVA_2147755886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.PVA!MTB"
        threat_id = "2147755886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 08 8b 45 ?? 33 d2 f7 75 ?? 0f be 84 15 ?? ff ff ff 33 c8 8b 45 ?? 03 45 ?? 88 08 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_PVB_2147756268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.PVB!MTB"
        threat_id = "2147756268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 b8 c1 ea 05 03 55 90 33 ca 8b 45 bc 2b c1 89 45 bc 8b 4d a4 2b 4d 8c 89 4d a4 eb}  //weight: 1, accuracy: High
        $x_1_2 = {ba 04 00 00 00 6b c2 00 8b 4d b4 8b 55 bc 89 14 01 b8 04 00 00 00 c1 e0 00 8b 4d b4 8b 55 b8 89 14 01 e9}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 b8 c1 e8 05 03 45 90 33 c8 8b 55 bc 2b d1 89 55 bc 8b 45 a4 2b 45 8c 89 45 a4 eb}  //weight: 1, accuracy: High
        $x_1_4 = {b9 04 00 00 00 6b d1 00 8b 45 b4 8b 4d bc 89 0c 10 ba 04 00 00 00 c1 e2 00 8b 45 b4 8b 4d b8 89 0c 10 e9}  //weight: 1, accuracy: High
        $x_1_5 = {8b 4d dc c1 e9 05 03 4d b8 33 c1 8b 4d e4 2b c8 89 4d e4 8b 45 d8 2b 45 b4 89 45 d8 eb}  //weight: 1, accuracy: High
        $x_1_6 = {6a 04 58 6b c0 00 8b 4d e0 8b 55 e4 89 14 01 6a 04 58 c1 e0 00 8b 4d e0 8b 55 dc 89 14 01 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_IStartSurf_PVC_2147756527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.PVC!MTB"
        threat_id = "2147756527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 14 8a 04 02 8b 55 10 32 c1 88 04 16 0f be f1 8b c6 c1 f8 02 83 e0 0f 83 f8 04 0f 83}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_DSA_2147760552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.DSA!MTB"
        threat_id = "2147760552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c3 01 f7 f3 89 45 ?? 68 ?? ?? ?? ?? 5a 0b d0 c1 e2 0a 89 55 03 00 8b 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c8 0c 39 45 ?? 0f 87 0a 00 8b 45 ?? 48 89 45 ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 40 36 8b 4d ?? 8b 04 01 89 45 e0 8b 45 e0 33 d2 b9 00 00 01 00 f7 f1 8b 45 e0 2b c2 89 45 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IStartSurf_DA_2147777650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IStartSurf.DA!MTB"
        threat_id = "2147777650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IStartSurf"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 24 00 00 00 8b 3e ba c3 00 00 00 0f 45 d0 33 c0 8d 8f ?? ?? ?? ?? 3b fe ?? ?? 3b ce ?? ?? 8b 0e 30 14 01 40 3d 00 06 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

