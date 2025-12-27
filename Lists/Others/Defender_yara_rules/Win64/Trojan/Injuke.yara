rule Trojan_Win64_Injuke_CRUV_2147848209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.CRUV!MTB"
        threat_id = "2147848209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 18 8b 44 24 08 99 83 e0 ?? 33 c2 2b c2 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injuke_CRUW_2147848211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.CRUW!MTB"
        threat_id = "2147848211"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 74 99 83 e0 ?? 33 c2 2b c2 85 c0 74 ?? 8b 44 24 74 ff c0 89 44 24 74 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injuke_NI_2147924817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.NI!MTB"
        threat_id = "2147924817"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {45 0f b7 df 44 0f af da 4d 63 db 49 63 fd 4d 01 cb 42 80 3c 1f 05}  //weight: 3, accuracy: High
        $x_2_2 = {45 0f b7 df 44 0f af da 4d 63 db 42 80 7c 1e 06 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injuke_GVA_2147940271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.GVA!MTB"
        threat_id = "2147940271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 89 c2 46 8a 1c 00 89 c1 80 e1 03 41 d2 cb 41 83 e2 0f 43 8a 0c 0a 80 e1 0f 44 30 d9 88 0c 32 48 ff c6 48 ff c0 48 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injuke_AHB_2147950172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.AHB!MTB"
        threat_id = "2147950172"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c8 c1 e9 1e 33 c1 69 c0 ?? ?? ?? ?? 03 c7 89 84 95 84 00 00 00 ff c7 48 ff c2 48 81 fa 70 02 00 00 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c8 c1 e9 1e 33 c1 69 c0 ?? ?? ?? ?? 03 c7 89 44 95 34 ff c7 48 ff c2 48 81 fa 70 02 00 00 7c}  //weight: 10, accuracy: Low
        $x_20_3 = {5c 44 42 47 c7 85 ?? ?? 00 00 42 75 66 66 c7 85 ?? ?? 00 00 65 72 70 2e c7 85 ?? ?? 00 00 64 6c 6c 00 4c 8d 85}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Injuke_MK_2147951461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.MK!MTB"
        threat_id = "2147951461"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 88 0c 10 8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 0f b6 04 10 83 f0 a5}  //weight: 20, accuracy: Low
        $x_10_2 = {8b 55 1c 48 8b 45 10 48 01 d0 44 0f b6 00 0f b6 0d ?? ?? ?? ?? 8b 55 1c 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injuke_AHD_2147958255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.AHD!MTB"
        threat_id = "2147958255"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {4c 8b c1 49 d1 e8 4d 8b c8 4d 03 c9 4e 39 24 ca 73 ?? 4a 8d 14 ca 48 83 c2 ?? 48 83 c8 ?? 49 2b c0 48 03 c8 eb}  //weight: 30, accuracy: Low
        $x_20_2 = {8b 42 0c 48 03 05 ?? ?? ?? ?? 4c 8d 45 ?? 33 d2 48 8b ce ff d0 8b f8 eb}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injuke_PGIN_2147959660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.PGIN!MTB"
        threat_id = "2147959660"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 44 24 08 48 3b 44 24 18 0f 83 47 00 00 00 48 8b 44 24 20 48 89 04 24 48 8b 44 24 08 31 c9 89 ca 48 f7 74 24 28 48 8b 04 24 44 0f b6 04 10 48 8b 44 24 10 48 8b 4c 24 08 0f b6 14 08 44 31 c2 88 14 08 48 8b 44 24 08 48 83 c0 01 48 89 44 24 08 e9}  //weight: 5, accuracy: High
        $x_5_2 = "_ScreenConnect" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

