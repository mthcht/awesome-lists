rule Trojan_Win64_Mint_SX_2147947159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mint.SX!MTB"
        threat_id = "2147947159"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0f b6 44 01 07 85 c0 75 43 0f b7 44 24 20 48 8b 4c 24 30 0f b6 44 01 05 88 44 24 28 0f b7 44 24 20 48 8b 4c 24 30 0f b6 44 01 04 88 44 24 29 0f b6 44 24 28 c1 e0 08 0f b6 4c 24 29 0b c1 48 8b 8c 24 80 00 00 00 66 89 41 10 eb 12}  //weight: 3, accuracy: High
        $x_2_2 = {48 8b 44 24 20 0f b6 00 89 04 24 8b 04 24 89 44 24 04 48 8b 44 24 20 48 ff c0 48 89 44 24 20 83 7c 24 04 00 74 1c 48 8b 44 24 08 48 c1 e0 05 48 03 44 24 08 48 63 0c 24 48 03 c1 48 89 44 24 08 eb be}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mint_AHB_2147948853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mint.AHB!MTB"
        threat_id = "2147948853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f be 04 17 48 ff c2 03 c3 69 c8 01 01 00 00 8b d9 c1 eb 06 33 d9 49 3b d0 75}  //weight: 10, accuracy: High
        $x_5_2 = {48 8b ca 49 8b c1 83 e1 07 48 2b c1 0f b6 00 41 30 04 10 48 ff c2 48 3b d7 72}  //weight: 5, accuracy: High
        $x_5_3 = {48 8b c1 83 e0 07 42 0f b6 04 00 30 04 0a 48 ff c1 48 3b cf 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Mint_ABM_2147960286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mint.ABM!MTB"
        threat_id = "2147960286"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4e 8b 34 ca 41 0f b6 2c 1e 4f 8b 34 c8 44 8d 7b ?? 41 83 e7 ?? 43 2a 2c 3e 41 89 df 41 83 e7 ?? 43 32 2c 3e 45 8d 34 1b 42 88 2c 30 48 83 c3 01 48 39 df}  //weight: 5, accuracy: Low
        $x_5_2 = {49 0f af c8 4c 01 c9 49 89 ca 49 c1 ea ?? 44 30 14 10 48 83 c2 01 48 81 fa}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mint_AB_2147961181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mint.AB!MTB"
        threat_id = "2147961181"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mint"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4f 8b 0c e6 47 0f b6 0c 01 4f 8b 14 e7 45 8d 58 05 41 83 e3 0f 47 2a 0c 1a 45 89 c3 41 83 e3 0f 47 32 0c 1a 46 8d 14 01 46 88 0c 17 49 83 c0 01 4c 39 c2 75 cb}  //weight: 5, accuracy: High
        $x_5_2 = {48 0f af c2 4c 01 c0 49 89 c1 49 c1 e9 38 44 30 0c 0f 48 83 c1 01 48 81 f9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

