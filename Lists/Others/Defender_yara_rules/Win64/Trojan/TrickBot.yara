rule Trojan_Win64_TrickBot_A_2147742281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickBot.A"
        threat_id = "2147742281"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 30 00 34 00 2e 00 31 00 36 00 38 00 2e 00 39 00 38 00 2e 00 32 00 30 00 36 00 2f 00 [0-32] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 38 00 35 00 2e 00 31 00 38 00 33 00 2e 00 39 00 38 00 2e 00 32 00 33 00 32 00 2f 00 [0-32] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 39 00 38 00 2e 00 32 00 33 00 2e 00 32 00 35 00 32 00 2e 00 31 00 31 00 37 00 2f 00 [0-32] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = "libgcj-16.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_TrickBot_CO_2147789540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickBot.CO!MTB"
        threat_id = "2147789540"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 ?? 48 8b 4c 24 ?? 48 03 c8 48 8b c1 8a 40 01 88 44 24 ?? 0f b6 44 24 ?? 83 e8 ?? 6b c0 ?? ba 7f 00 00 00 8b c8 e8 ?? ?? ?? ?? 48 8b 4c 24 ?? 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 41 01 eb a8}  //weight: 1, accuracy: Low
        $x_1_2 = {99 b9 7f 00 00 00 f7 f9 8b c2 88 44 24 ?? b8 01 00 00 00 48 6b c0 01 48 8d 0d ?? ?? ?? ?? 0f b6 04 01 6b c0 ?? 83 c0 ?? 99 b9 7f 00 00 00 f7 f9 8b c2 88 44 24 ?? b8 01 00 00 00 48 6b c0 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TrickBot_FE_2147797064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickBot.FE!MTB"
        threat_id = "2147797064"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 d2 6b 6e 00 00 44 2b c2 49 63 d0 44 89 84 24 90 00 00 00 42 0f b6 04 32 43 88 44 0d 00 48 8b 44 24 28 42 88 0c 32 48 03 c2 46 0f b6 04 30 4b 8d 04 0c 42 0f b6 0c 30 b8 95 b3 61 94 44 03 c1 48 8b 8c 24 88 00 00 00 41 f7 e0 c1 ea 0e 69 d2 6b 6e 00 00 44 2b c2 49 63 c0 48 03 44 24 30 48 03 c5 48 03 c7 48 03 c6 42 0f b6 04 30 41 30 04 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TrickBot_GI_2147798749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickBot.GI!MTB"
        threat_id = "2147798749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 63 c2 4d 8d 5b 01 48 8b c7 41 ff c2 49 f7 e0 48 c1 ea 02 48 6b ca 16 4c 2b c1 42 0f b6 44 84 20 41 30 43 ff 41 81 fa 00 16 03 00 72}  //weight: 1, accuracy: High
        $x_1_2 = "SreismeoW" ascii //weight: 1
        $x_1_3 = "adabyviuikeefrru" ascii //weight: 1
        $x_1_4 = "zoogdvmpweg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TrickBot_RDA_2147933844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickBot.RDA!MTB"
        threat_id = "2147933844"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 44 24 48 49 8b 0c f7 4c 89 f2 48 d3 fa 30 54 18 08 48 83 fe 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TrickBot_ARAX_2147958361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickBot.ARAX!MTB"
        threat_id = "2147958361"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 0f b6 03 48 ff c1 41 ff ca 88 44 0c 47 ff c3 49 ff c3 48 83 f9 04 0f 85 95 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {32 c2 88 44 24 41 0f b7 01 66 89 46 fd 0f b6 41 02 33 c9 88 46 ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_TrickBot_ARAC_2147959970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrickBot.ARAC!MTB"
        threat_id = "2147959970"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrickBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 c2 88 44 24 41 0f b7 01 66 89 46 fd 0f b6 41 02 33 c9 88 46 ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

