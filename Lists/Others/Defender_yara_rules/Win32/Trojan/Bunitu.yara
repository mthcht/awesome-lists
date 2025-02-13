rule Trojan_Win32_Bunitu_AD_2147734888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.AD!MTB"
        threat_id = "2147734888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 14 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 45 fc 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 89 4d f4 eb 00 c7 05 ?? ?? ?? ?? 00 00 00 00 8b 55 f4 89 15 ?? ?? ?? ?? 8b 45 fc a3}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 06 00 00 00 85 c9 74 ?? eb 00 8b 15 ?? ?? ?? ?? 3b 55 08 72 ?? eb ?? 8b 45 fc 03 05 ?? ?? ?? ?? c6 00 00 c7 45 ?? ?? 00 00 00 e8 ?? ?? ?? ?? c7 45 ?? ?? 00 00 00 8b 0d ?? ?? ?? ?? 83 c1 01 89 0d ?? ?? ?? ?? eb ?? 8b e5 5d}  //weight: 1, accuracy: Low
        $x_2_3 = {0f b6 0c 0a 15 00 0f b6 04 02 20 00 8b 15 ?? ?? ?? ?? 88 04 0a 8b e5 5d}  //weight: 2, accuracy: Low
        $x_2_4 = "rr3r3333233333xA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_DSK_2147741680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.DSK!MTB"
        threat_id = "2147741680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a1 38 1b 55 00 8b c0 8b ca 8b c0 a3 54 1b 55 00 8b c0 8b 3d 54 1b 55 00 33 f9 89 3d 54 1b 55 00 8b c0 a1 54 1b 55 00 c7 05 38 1b 55 00 00 00 00 00 01 05 38 1b 55 00 8b 0d 48 1b 55 00 8b 15 38 1b 55 00 89 11}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_DSK_2147741680_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.DSK!MTB"
        threat_id = "2147741680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d2 8b ca 8b d2 ff 35 ?? ?? ?? ?? 8b d2 8f 45 fc 8b d2 31 4d fc 8b d2 8b 45 fc 8b d2 8b c8 8b d2 b8 00 00 00 00 03 c1 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_VDSK_2147742756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.VDSK!MTB"
        threat_id = "2147742756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 f8 33 f2 8b d6 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVD_2147747811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVD!MTB"
        threat_id = "2147747811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d7 8b ca b8 ff 01 00 00 03 c1 2d ff 01 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
        $x_2_2 = {83 e8 01 33 c9 03 45 e8 13 4d ec 89 45 e4 8b 15 ?? ?? ?? ?? 81 c2 34 76 1a 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 e0 8b 0d ?? ?? ?? ?? 89 88 85 f8 ff ff 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 45 fc 33 45 f8 89 45 fc 8b 45 f4 2b 45 fc 89 45 f4 8b 45 e8 2b 45 c8 89 45 e8 c7 05 ?? ?? ?? ?? ca e3 40 df e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Bunitu_PVS_2147751536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVS!MTB"
        threat_id = "2147751536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c0 33 3d ?? ?? ?? ?? 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 4d 08 89 31 8b 55 08 8b 02 2d 36 a6 06 00 8b 4d 08 89 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Bunitu_BS_2147751751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.BS!MTB"
        threat_id = "2147751751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 03 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {03 ca 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 0a a1 ?? ?? ?? ?? 83 c0 01 a3 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_BA_2147752065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.BA!MTB"
        threat_id = "2147752065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ea 2d ad 00 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {03 f8 68 6f d0 06 00 ff 15 ?? ?? ?? ?? 03 45 ?? 8b 55 ?? 8a 0c 32 88 0c 38 8b 55 ?? 83 c2 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVK_2147752444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVK!MTB"
        threat_id = "2147752444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 44 24 07 88 99 ?? ?? ?? ?? 0f b6 9a ?? ?? ?? ?? 03 d8 81 f9 59 22 00 00 73}  //weight: 2, accuracy: Low
        $x_2_2 = {8b ff 33 3d ?? ?? ?? ?? 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
        $x_2_3 = {b4 ca 48 21 5e da 08 ba ?? ?? ?? ?? 80 f3 09 eb}  //weight: 2, accuracy: Low
        $x_2_4 = {f6 d2 0a ca 22 cb 88 08 83 c0 01 83 6c 24 ?? 01 89 44 24 ?? 0f 85 04 00 8b 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Bunitu_KPV_2147752583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.KPV!MTB"
        threat_id = "2147752583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b db 33 3d ?? ?? ?? ?? 8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_DSP_2147753369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.DSP!MTB"
        threat_id = "2147753369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c9 33 3d ?? ?? ?? ?? 8b c9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cf 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVR_2147754534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVR!MTB"
        threat_id = "2147754534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c8 8b d1 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 8b e5 5d 0a 00 8b c7 eb ?? 33 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVF_2147754784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVF!MTB"
        threat_id = "2147754784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c7 eb 00 eb 00 33 05 ?? ?? ?? ?? 8b c8 8b d1 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_GKM_2147755025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.GKM!MTB"
        threat_id = "2147755025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 04 30 f7 d8 8b 8d 7c ff ff ff 0f be 11 2b d0 8b 85 7c ff ff ff 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVG_2147755367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVG!MTB"
        threat_id = "2147755367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 0c 30 8b 55 e8 0f be 02 03 c1 8b 4d e8 88 01 8b 15 ?? ?? ?? ?? 83 c2 01 89 15 ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVH_2147755414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVH!MTB"
        threat_id = "2147755414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 03 55 f0 8b 45 f4 03 45 f8 8b 4d fc 8a 00 88 04 11 8b 4d f8 83 c1 01 89 4d f8 eb}  //weight: 1, accuracy: High
        $x_1_2 = {8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 25 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 01 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVI_2147755546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVI!MTB"
        threat_id = "2147755546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ba 2c 23 a6 02 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVJ_2147755671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVJ!MTB"
        threat_id = "2147755671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d fc 8d 94 01 ?? ?? ?? ?? 89 55 ec 8b 45 ec a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d fc 83 c1 04 89 4d fc ba bd 01 00 00 85 d2 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVL_2147755672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVL!MTB"
        threat_id = "2147755672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ba f3 5b 0a 00 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVM_2147755699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVM!MTB"
        threat_id = "2147755699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ba 11 7f 01 00 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5d c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_PVN_2147755786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.PVN!MTB"
        threat_id = "2147755786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c0 33 05 ?? ?? ?? ?? 8b c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c0 8b c8 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bunitu_RPI_2147829271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bunitu.RPI!MTB"
        threat_id = "2147829271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bunitu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 89 85 30 fe ff ff 8b 4d f4 03 8d 30 fe ff ff 0f b6 11 89 95 34 fe ff ff 8b 45 ec 03 85 30 fe ff ff 8a 8d 34 fe ff ff 88 08 8b 55 f8 83 c2 01 89 55 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

