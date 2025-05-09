rule Trojan_Win64_Xmrig_AX_2147839585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xmrig.AX!MTB"
        threat_id = "2147839585"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b5 31 d9 88 99 b0 b7 6f 79 ?? ?? dd 3f f9 ad d0 c4 86 14 8e 9e 07 ?? ?? e7 3b d6 f6 01 85 f5 3c 0d dc 57 9f 10 b9 19 ed 41 52 1e db b2 4d 07 21 30 b5 e2 bf fe 80 2a ac c1 cd 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Xmrig_MA_2147842628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xmrig.MA!MTB"
        threat_id = "2147842628"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {e9 3f 01 00 00 4c 8d 1d e4 ff ff ff eb 03 30 af ba 4c 8d 15 e8 ff ff ff eb 02 1a ab 80 3d 38 04 00 00 00 eb 03 b9 16 9b 4d 0f 45 d3 eb 01 a9 b8 b0 61 17 00 eb 02 4f bc 4d 8b e2 eb 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Xmrig_AXR_2147911533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xmrig.AXR!MTB"
        threat_id = "2147911533"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 48 8b 5c 24 48 48 8b 4c 24 30 48 8d 3d c9 e1 07 00 be 18 00 00 00 e8 d9 4e df ff 48 89 44 24 58 48 89 5c 24 40 48 8b 4c 24 30 48 8d 3d b2 cd 07 00 be 16 00 00 00 31 c0 48 8b 5c 24 48 e8 b2 4e df ff 48 89 44 24 50 48 89 5c 24 38 48 89 c1 48 89 df 48 8d 05 b4 44 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Xmrig_AXR_2147911533_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xmrig.AXR!MTB"
        threat_id = "2147911533"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 db 48 89 5c 24 40 48 89 5c 24 48 41 b8 15 00 00 00 48 8d 15 5d 6c 04 00 48 8d 4c 24 30 e8 ?? ?? ?? ?? ?? 0f 57 c0 0f 11 44 24 50 48 89 5c 24 60 48 89 5c 24 68 41 b8 16 00 00 00 48 8d 15 4b 6c 04 00 48 8d 4c 24 50}  //weight: 3, accuracy: Low
        $x_2_2 = {0f 57 c0 0f 11 45 d0 48 89 5d e0 48 89 5d e8 41 b8 15 00 00 00 48 8d 15 f8 6b 04 00 48 8d 4d d0 e8 ?? ?? ?? ?? ?? 0f 57 c0 0f 11 45 f0 48 89 5d 00 48 89 5d 08 41 b8 17 00 00 00 48 8d 15 ea 6b 04 00 48 8d 4d f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

