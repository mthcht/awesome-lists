rule Trojan_Win64_ACRStealer_ETL_2147944753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.ETL!MTB"
        threat_id = "2147944753"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 44 24 20 48 c7 40 10 12 00 00 00 48 8d 0d f8 a0 01 00 48 89 48 08 48 8b 4c 24 38 48 89 4c 24 30 48 8d 05 40 8d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ACRStealer_GVA_2147959906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.GVA!MTB"
        threat_id = "2147959906"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 15 e0 ac 81 00 48 8b 45 f8 48 01 d0 44 0f b6 00 b9 76 00 00 00 48 8b 45 f8 ba 00 00 00 00 48 f7 f1 48 8d 05 3d b1 81 00 0f b6 0c 02 48 8b 55 f0 48 8b 45 f8 48 01 d0 44 89 c2 31 ca 88 10 48 8d 3f 4d 87 d2 48 83 45 f8 01 b8 16 00 00 00 48 39 45 f8 72 aa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ACRStealer_NUA_2147965160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.NUA!MTB"
        threat_id = "2147965160"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 48 0f 2a c0 0f 28 c8 f3 0f 59 4b 1c 0f 2f ca 72 0c f3 0f 5c ca 0f 2f ca}  //weight: 1, accuracy: High
        $x_2_2 = {f6 44 01 03 0f 74 0b 0f b6 44 01 03 83 e0 f0 4c 03 c8 4c 33 ca 49 8b c9 5b e9 f1 3a ff ff cc}  //weight: 2, accuracy: High
        $x_2_3 = {48 89 9c 24 b0 40 00 00 48 89 ac 24 b8 40 00 00 48 8b 05 0a 06 05 00 48 33 c4 48 89 84 24 60 40 00 00 4c 8b f2 48 8b d9 48 85 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ACRStealer_AHA_2147966057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.AHA!MTB"
        threat_id = "2147966057"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {45 89 ca 41 09 f1 44 21 d6 41 29 f1 45 31 c8 44 88 04 38 48 8d 57 ff}  //weight: 30, accuracy: High
        $x_20_2 = {0f b6 30 0f b6 7c 24 ?? 31 f7 40 88 38 31 d2 eb}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ACRStealer_AHC_2147966356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.AHC!MTB"
        threat_id = "2147966356"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {89 cb c1 e1 ?? 31 d9 89 cb c1 e9 ?? 31 d9 89 cb c1 e1 ?? 31 d9 90 89 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 85 c9 75}  //weight: 30, accuracy: Low
        $x_20_2 = {44 0f b6 24 16 45 31 d4 45 88 24 18 48 ff c3 4c 89 c0 4c 89 da 48 39 d9 7e}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ACRStealer_VGZ_2147966790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.VGZ!MTB"
        threat_id = "2147966790"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 54 04 46 0f b6 74 04 1c 31 f2 c0 c2 04 88 54 04 46 48 ff c0 48 83 f8 2a 7c e4}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 94 04 a3 00 00 00 0f b6 74 04 46 31 d6 40 88 b4 04 a3 00 00 00 48 ff c0 48 83 f8 10 7c e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_ACRStealer_VGX_2147966891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.VGX!MTB"
        threat_id = "2147966891"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d1 89 ca c1 ea ?? 31 d1 89 ca c1 e2 ?? 31 d1 0f b6 54 04 ?? 89 ce c1 ee 10 31 ?? ?? ?? ?? ?? ?? 48 ff c0 48 83 f8 ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ACRStealer_VGA_2147967839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ACRStealer.VGA!MTB"
        threat_id = "2147967839"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ACRStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 da 89 d3 c1 e3 ?? 31 da 0f b6 1c ?? 89 d6 c1 ee 10 31 f3 88 1c 08 48 ff c1 48 83 f9 ?? 7c}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b6 14 08 0f b6 74 0c 10 31 f2 c0 c2 04 88 14 08 48 ff c1 48 83 f9 28 7c e6}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 14 01 0f b6 5c 0c 2a f7 d3 31 d3 88 1c 08 48 ff c1 48 83 f9 10 7c e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

