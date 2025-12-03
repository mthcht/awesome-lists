rule Trojan_Win64_EggStremeLoader_C_2147952130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.C!MTB"
        threat_id = "2147952130"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 63 ca 8a 04 31 41 88 04 30 44 88 0c 31 41 0f b6 0c 30 49 03 c9 0f b6 c1 8a 0c 30 41 30 0c 24 4d 03 e3 4d 2b d3 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EggStremeLoader_CA_2147952134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.CA!MTB"
        threat_id = "2147952134"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 48 8d 05 ?? ?? ?? ?? 8a 04 01 34 dd 88 84 0d ?? ?? ?? ?? 48 ff c1 48 83 f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EggStremeLoader_G_2147954810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.G!dha"
        threat_id = "2147954810"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 41 0a 48 ba [0-16] 66 c7 41 14 41 b8 [0-16] 66 c7 41 1a 49 b9}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 41 29 48 83 ec 20 [0-16] 66 c7 41 2d 48 b8 [0-16] 66 c7 41 37 ff d0}  //weight: 1, accuracy: Low
        $x_2_3 = {b9 48 b9 00 00 66 89 8c 24 c0 00 00 00 [0-16] b9 48 ba 00 00 [0-24] b8 41 b8 00 00 [0-24] b8 49 b9 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_EggStremeLoader_I_2147956489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.I!dha"
        threat_id = "2147956489"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 48 9a e5 [0-6] b9 b6 6e 1a [0-6] 5c 59 c7 66 [0-6] 08 c2 df 19 [0-6] 37 ce 4a 40 [0-6] 75 fc 5e e3 [0-6] 09 6e f1 61 [0-6] fd ca 68 67}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 8f fc 2d 47 86 c8 61 89 04 8f 48 ff c1 48 83 f9 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EggStremeLoader_H_2147958689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.H!dha"
        threat_id = "2147958689"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 62 e6 ef [0-6] a4 f6 f6 76 [0-6] c5 43 0e c1 [0-6] bd f7 59 9f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 8f fc 2d 47 86 c8 61 89 04 8f 48 ff c1 48 83 f9 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EggStremeLoader_J_2147958690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.J!dha"
        threat_id = "2147958690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 46 0a 1e [0-6] 2c 3a 77 3c [0-6] 5f 59 17 a4 [0-6] 4a 42 68 50 [0-6] 7e 73 04 9c}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c7 41 8d 4b 01 83 e0 07 4c 8d 44 24 ?? 4c 03 c7 48 ff c7 42 8a 14 10 41 8a c3 43 32 14 01 02 c0 02 c8 41 ff c3 32 d1 41 88 10 41 83 fb 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EggStremeLoader_K_2147958691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.K!dha"
        threat_id = "2147958691"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 0e aa b7 [0-6] 5f ec 70 90 [0-6] 69 66 f6 c8 [0-6] 0c bd 33 ef [0-6] 30 07 f9 2a [0-6] 2b c2 49 b7 [0-6] 59 0f 30 60}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c7 41 8d 4b 01 83 e0 07 4c 8d 44 24 ?? 4c 03 c7 48 ff c7 42 8a 14 10 41 8a c3 43 32 14 01 02 c0 02 c8 41 ff c3 32 d1 41 88 10 41 83 fb 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_EggStremeLoader_L_2147958692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/EggStremeLoader.L!dha"
        threat_id = "2147958692"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "EggStremeLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 55 c0 c8 04 0f b6 c8 6b c2 0d 83 c0 1d}  //weight: 1, accuracy: High
        $x_1_2 = {69 0b 06 0c 72 73 eb 02 c4 b6 c7 0b 8e 3c 99 19 d6 95 34 fe 37 b2 c8 c3 29 fe 55 bc be d2 66 53}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

