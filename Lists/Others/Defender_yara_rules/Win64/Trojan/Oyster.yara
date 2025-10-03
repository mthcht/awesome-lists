rule Trojan_Win64_Oyster_AA_2147908622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.AA!MTB"
        threat_id = "2147908622"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d0 8b 85 ?? ?? ?? ?? 48 89 54 c5 ?? 83 85 ?? ?? ?? ?? 01 81 bd ?? ?? ?? ?? ?? ?? 00 00 76 ?? 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {48 63 d0 8b 85 ?? ?? ?? ?? 48 89 54 c5 ?? 83 85 ?? ?? ?? ?? 01 81 bd ?? ?? ?? ?? ?? ?? 00 00 0f 86 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Oyster_A_2147913092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.A"
        threat_id = "2147913092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 58 45 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 54 65 73 74 00 43 4f 4d 00 6f 70 65 6e 00 74 65 6d 70 00 25 73 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_YAD_2147953809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.YAD!MTB"
        threat_id = "2147953809"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "@USVWATAUAVAW" ascii //weight: 20
        $x_1_2 = {48 b8 24 07 c0 e9 03 48 c7 c3}  //weight: 1, accuracy: High
        $x_1_3 = {48 b8 72 17 de a6 5c 28 c7 56}  //weight: 1, accuracy: High
        $x_1_4 = {48 b8 6f 15 4a 89 86 dc 95 a1}  //weight: 1, accuracy: High
        $x_1_5 = {48 b8 a7 e0 9c fe 3f f0 5c cd}  //weight: 1, accuracy: High
        $x_1_6 = {48 b8 35 5b 03 93 e9 1f ad fe}  //weight: 1, accuracy: High
        $x_1_7 = {48 b8 4d 58 c1 08 47 6e 01 e1}  //weight: 1, accuracy: High
        $x_1_8 = {48 b8 08 91 12 09 60 74 52 ac}  //weight: 1, accuracy: High
        $x_1_9 = {48 b8 2d 13 71 8e 9d 75 9c 30}  //weight: 1, accuracy: High
        $x_1_10 = {48 b8 37 4a 89 16 31 10 10 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Oyster_Z_2147953906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.Z!MTB"
        threat_id = "2147953906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 44 89 f8 41 ff c7 44 88}  //weight: 1, accuracy: High
        $x_1_2 = {48 b8 0f b6 07 41 c1 e2 08 ff}  //weight: 1, accuracy: High
        $x_1_3 = {49 bf 0f b6 07 41 c1 e2 08 41}  //weight: 1, accuracy: High
        $x_1_4 = {48 b8 89 d0 66 c1 e8 05 8d 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZA_2147953907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZA!MTB"
        threat_id = "2147953907"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8d 4c 24 48 c7 44 24 28 40 00 00 00 45 33 c0 48 c7 44 24 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZB_2147953908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZB!MTB"
        threat_id = "2147953908"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 53 50 48 85 d2 74 30 66 83 7b 48 00 76 29 41 b8 40 00 00 00 48 8d 4c 24 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZC_2147953909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZC!MTB"
        threat_id = "2147953909"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 89 44 5c 42 0f b6 01 84 c0 74 15 66 89 44 5c 44 48 83 c1 03 48 83 c3 03 48 83 fb 3f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZD_2147953912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZD!MTB"
        threat_id = "2147953912"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 44 24 50 45 33 c9 89 44 24 48 45 33 c0 89 44 24 40 33 d2 89 44 24 38 33 c9 89 44 24 30 48 89 44 24 28 89 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZF_2147953913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZF!MTB"
        threat_id = "2147953913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 41 39 ff 73 13 48 8b 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_ZE_2147953914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.ZE!MTB"
        threat_id = "2147953914"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 48 8d 34 68 77 1a}  //weight: 1, accuracy: High
        $x_1_2 = "DllRegisterServer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

