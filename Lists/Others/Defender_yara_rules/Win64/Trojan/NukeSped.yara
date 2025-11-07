rule Trojan_Win64_NukeSped_SIB_2147806404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NukeSped.SIB!MTB"
        threat_id = "2147806404"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d9 48 2b f1 4c 8b c1 41 b9 ?? ?? ?? ?? [0-5] b9 ?? ?? ?? ?? [0-16] 42 0f b6 04 06 41 30 00 49 ff c0 48 83 e9 01 75 ?? 49 83 e9 01 75 ?? 48 8d 7e 10 8d 69 ?? 4c 8d 35 ?? ?? ?? ?? [0-16] 4c 8b c3 41 b9 ?? ?? ?? ?? [0-10] 49 8b c8 ba ?? ?? ?? ?? [0-10] 0f b6 01 48 8d 49 ?? 42 0f b6 04 30 88 41 ?? 48 83 ea 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {49 ff c0 49 83 e9 01 75 ?? 0f b6 4b ?? 0f b6 43 ?? 88 43 ?? 0f b6 43 ?? 88 43 ?? 0f b6 43 ?? 88 43 ?? 0f b6 43 ?? 88 4b ?? 0f b6 4b ?? 88 43 ?? 0f b6 43 ?? 88 4b ?? 0f b6 4b ?? 88 43 ?? 0f b6 43 ?? 88 4b ?? 0f b6 4b ?? 88 43 ?? 0f b6 43 ?? 88 43 ?? 0f b6 43 ?? 88 4b}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8d 41 02 bd ?? ?? ?? ?? [0-5] 0f b6 70 ?? 44 0f b6 48 ?? 44 0f b6 c6 0f b6 78 ?? 45 32 c1 44 0f b6 18 48 8d 40 ?? 41 0f b6 c8 44 0f b6 d7 c0 e9 ?? 45 02 c0 0f b6 c9 45 32 d3 6b d1 ?? 41 0f b6 da 40 32 de 41 32 d9 41 32 d0 45 0f b6 c1 40 32 d6 45 32 c3 32 d3 41 0f b6 c8 88 50 ?? 40 32 f7 c0 e9 07 45 02 c0 0f b6 c9 6b d1 ?? 41 0f b6 ca c0 e9 ?? 45 02 d2 0f b6 c9 41 32 d0 41 32 d1 32 d3 88 50 ?? 6b d1 ?? 40 0f b6 ce c0 e9 ?? 40 02 f6 0f b6 c9 41 32 d2 41 32 d3 32 d3 88 50 ?? 6b d1 ?? 40 32 d6 40 32 d7 32 d3 88 50 ?? 48 83 ed ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NukeSped_LKV_2147897411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NukeSped.LKV!MTB"
        threat_id = "2147897411"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c0 44 89 83 [0-9] 00 00 89 83 ?? ?? 00 00 41 8b c0 41 31 43 ?? 4a 8d 04 1e 48 3d ?? ?? ?? 00 0f 86}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 2b cf 8b 04 0a 48 83 c1 08 49 ff c8 89 41 f4 41 8b 44 09 f8 89 41 f8 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_NukeSped_DA_2147930009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NukeSped.DA!MTB"
        threat_id = "2147930009"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 43 01 ff ce 0f b6 0c 28 43 30 0c 26 41 ff c6 0f b6 43 01 fe c0 88 43 01 3c 40 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NukeSped_GXF_2147956305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NukeSped.GXF!MTB"
        threat_id = "2147956305"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5a 4e 33 36 33 4e 64 64 00 6e 74 64 6c 6c}  //weight: 5, accuracy: High
        $x_5_2 = {45 36 50 20 43 4d 5c 31 73 46 45 6f 42 44 54 57 33 4b 6f 31 45 00 00 00 00 74 78 34}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NukeSped_GXG_2147956319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NukeSped.GXG!MTB"
        threat_id = "2147956319"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6b 65 72 6e c7 85 ?? ?? ?? ?? 65 6c 33 32 c7 85 ?? ?? ?? ?? 2e 64 6c 6c c6 85 ?? ?? ?? ?? 00 48 8d 8d ?? ?? ?? ?? ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {48 8d 45 cb 48 89 44 24 40 44 89 7c 24 38 4c 89 7c 24 30 8b 43 10 89 44 24 28 48 89 4c 24 20 45 33 c9 44 8b 47 10 48 8b 4d cf ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NukeSped_CH_2147956320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NukeSped.CH!MTB"
        threat_id = "2147956320"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 84 29 ?? ?? ?? ?? ff c2 32 04 19 88 04 39 8b ca 48 3b ce 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NukeSped_GVA_2147956339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NukeSped.GVA!MTB"
        threat_id = "2147956339"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 3b df 77 28 48 8d 43 0f 48 3b c5 72 1f 48 8b c3 ba 10 00 00 00 0f 1f 44 00 00 0f b6 0c 07 30 08 48 8d 40 01 48 83 ea 01}  //weight: 2, accuracy: High
        $x_1_2 = {5c 6d 69 63 72 6f 73 6f 66 74 20 73 68 61 72 65 64 5c 69 6e 6b [0-16] 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_3 = "\\dinput.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_NukeSped_GVB_2147956995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NukeSped.GVB!MTB"
        threat_id = "2147956995"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c2 ff c9 24 3f c1 ea 06 0c 80 41 88 00 49 ff c8 85 c9 7f ea 43 0a 94 8b 78 4a 06 00 41 88 10 44 0f b6 04 24 45 8b c8 41 8b c8 49 c1 e9 03 83 e1 07 41 0f b6 14 29 0f ab ca 41 88 14 29 49 8b c2 eb 2d}  //weight: 2, accuracy: High
        $x_1_2 = {48 8b 43 08 0f b6 14 07 8b ca 83 e2 07 48 c1 e9 03 0f b6 04 29 0f ab d0 88 04 29 49 8d 42 01 48 8b 4c 24 08 48 33 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

