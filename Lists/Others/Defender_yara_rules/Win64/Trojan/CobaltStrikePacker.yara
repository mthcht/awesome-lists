rule Trojan_Win64_CobaltStrikePacker_AA_2147839545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikePacker.AA!MTB"
        threat_id = "2147839545"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c7 c0 00 00 00 00 48 31 db 48 83 e1 00 48 29 ff 48 8b 14 24 48 8d 64 24 08 04 ?? 48 89 c6 04 ?? ff cf c1 ef ?? 48 31 fa 48 01 c8 48 8d 49 ?? 48 ff c0 48 29 c8 48 39 f9 75 ?? 84 c0 48 31 ca 48 83 e1 ?? 48 ff c8 88 02 48 31 fa 48 8d 5b ?? 48 39 f3 75 ?? 48 29 f3 48 01 da 48 31 fa ff e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikePacker_AB_2147839911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikePacker.AB!MTB"
        threat_id = "2147839911"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b f0 48 89 00 48 89 40 08 48 89 44 24 ?? 33 d2 8b ?? 8b c2 45 03 fd 48 8d 2d ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 49 b8 aa aa aa aa aa aa aa 0a 66 0f 1f 84 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b f0 48 89 00 48 89 40 08 48 89 44 24 ?? 33 d2 8b ?? 8b ?? 8b ?? 45 03 ?? 4c 8d 3d ?? ?? ?? ?? 4c 8d 05 ?? ?? ?? ?? 49 b9 aa aa aa aa aa aa aa 0a 0f 1f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {44 0f b6 24 ?? 44 32 65 00 4c 39 44 24 38 0f 84 ?? ?? ?? ?? 48 8d 44 24 30 48 89 44 24 20 48 89 54 24 28 b9 18 00 00 00 e8 ?? ?? ?? ?? 44 88 60 10 48 ff 44 24 38 48 8b 4e 08 48 89 30 48 89 48 08 33 d2 48 89 54 24 28 48 89 46 08 48 89 01 48 8b 74 24 30 48 8d 0d ?? ?? ?? ?? 49 b8 aa aa aa aa aa aa aa 0a eb}  //weight: 1, accuracy: Low
        $x_1_4 = {46 0f b6 2c ?? 45 32 2f 4c 39 4c 24 40 0f 84 ?? ?? ?? ?? 48 8d 44 24 38 48 89 44 24 28 48 89 54 24 30 b9 18 00 00 00 e8 ?? ?? ?? ?? 44 88 68 10 48 ff 44 24 40 48 8b 4e 08 48 89 30 48 89 48 08 33 d2 48 89 54 24 30 48 89 46 08 48 89 01 48 8b 74 24 38 44 8b 6c 24 20 4c 8d 05 ?? ?? ?? ?? 49 b9 aa aa aa aa aa aa aa 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_CobaltStrikePacker_AC_2147840074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikePacker.AC!MTB"
        threat_id = "2147840074"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 8c 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 8b 84 24 ?? ?? ?? ?? 83 c0 01 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 39 84 24 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 48 63 84 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 8b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikePacker_AE_2147840539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikePacker.AE!MTB"
        threat_id = "2147840539"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d8 48 69 f3 ?? ?? ?? ?? 48 89 f1 48 c1 e9 3f 48 c1 fe 23 01 ce c1 e6 02 8d 0c f6 29 cb 48 63 cb 42 0f b6 0c 01 32 0c 02 88 0c 07 48 ff c0 8b 8d ?? ?? ?? ?? 48 39 c8 48 8b 95 ?? ?? ?? ?? 48 63 d8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c2 83 e2 07 0f b6 14 17 32 14 06 41 88 14 04 48 83 c0 01 48 39 c3 75 e6 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrikePacker_DBD_2147840680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikePacker.DBD!MTB"
        threat_id = "2147840680"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {4c 8d 05 5d 8b 02 00 ba 00 00 00 00 b9 00 00 00 00 e8 0b 00 00 00 b8 00 00 00 00 48 83 c4 20}  //weight: 3, accuracy: High
        $x_3_2 = {48 89 8d 20 04 00 00 48 89 95 28 04 00 00 4c 89 85 30 04 00 00 44 89 8d 38 04 00 00 48 8d 05 1f 8b 02 00 48 89 85 e8 03 00 00 c7 85 e4 03 00 00 62 4a 2b 97 48 c7 85 f8 03 00 00 00 00 00 00 48 c7 85 d8 03 00 00 00 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikePacker_AF_2147841412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikePacker.AF!MTB"
        threat_id = "2147841412"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c3 31 c0 48 89 c2 83 e2 07 8a 54 15 00 32 14 07 88 14 03 48 ff c0 39 c6 7f e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CobaltStrikePacker_AY_2147842311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikePacker.AY!MTB"
        threat_id = "2147842311"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c9 31 88 ?? ?? ?? ?? 48 8b 88 ?? ?? ?? ?? 46 8b 04 09 49 83 c1 04 44 0f af 40 ?? 8b 48 ?? 2b 88 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 01 48 ?? 48 63 50 ?? 48 8b 88 ?? ?? ?? ?? 44 88 04 0a ff 40 ?? 8b 90 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 83 ea ?? 44 8b 80 ?? ?? ?? ?? 0f af ca 89 88 ?? ?? ?? ?? 8b 50 ?? 83 c2 ?? 41 03 d0 01 50 ?? 44 33 40 ?? 44 01 80 ?? ?? ?? ?? 8b 48 ?? 2b 48 ?? 81 f1 ?? ?? ?? ?? 01 88 ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 8b 88}  //weight: 1, accuracy: Low
        $x_1_2 = {88 14 01 41 8b d0 ff 83 ?? ?? ?? ?? 48 63 8b ?? ?? ?? ?? 48 8b 83 ?? ?? ?? ?? c1 ea 08 88 14 01 ff 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 2b 43 ?? 2d ?? ?? ?? ?? 01 43 ?? 48 63 93 ?? ?? ?? ?? 48 8b 8b ?? ?? ?? ?? 44 88 04 0a ff 83 ?? ?? ?? ?? 8b 4b ?? 81 f1 ?? ?? ?? ?? 29 4b ?? 49 81 f9 ?? ?? ?? ?? 8b 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CobaltStrikePacker_AH_2147844769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CobaltStrikePacker.AH!MTB"
        threat_id = "2147844769"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CobaltStrikePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 03 0f b6 c2 0f b6 53 ?? 0f af d0 48 8b 83 ?? ?? ?? ?? 88 14 01 ff 43 ?? 8b 83 ?? ?? ?? ?? 03 43 ?? 31 83 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 48 ?? 8b 83 ?? ?? ?? ?? 83 f1 01 09 8b ?? ?? ?? ?? 83 f0 ?? 09 43 ?? 49 81 f8 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 8b 81 ?? ?? ?? ?? 03 83 ?? ?? ?? ?? 35 ?? ?? ?? ?? 29 41 ?? 48 8b 83 ?? ?? ?? ?? 8b 4b ?? 33 8b ?? ?? ?? ?? 41 8b 14 00 49 83 c0 04 8b 83 ?? ?? ?? ?? 33 83 ?? ?? ?? ?? 83 e8 ?? 09 43 ?? 8b 83 ?? ?? ?? ?? 0f af c1 48 63 4b ?? 89 83 ?? ?? ?? ?? 8b 43 ?? 2b 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

