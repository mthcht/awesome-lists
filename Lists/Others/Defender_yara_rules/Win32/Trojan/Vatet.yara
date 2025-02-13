rule Trojan_Win32_Vatet_B_2147751647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vatet.B!dha"
        threat_id = "2147751647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vatet"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4e 00 6f 00 74 00 65 00 70 00 61 00 64 00 [0-48] 25 00 6c 00 64 00 [0-48] 45 00 44 00 49 00 54 00 [0-112] 63 00 6f 00 6d 00 6d 00 64 00 6c 00 67 00 5f 00 46 00 69 00 6e 00 64 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 6f 77 6e 6c 6f 61 64 73 5c 6e 6f 74 65 70 61 64 2d 6d 61 73 74 65 72 5c [0-16] 5c 6e 6f 74 65 70 61 64 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 64 61 74 00 5c 5c [0-9] 2e [0-9] 2e [0-9] 2e [0-9] 5c [0-144] 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Vatet_D_2147752884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vatet.D!MTB"
        threat_id = "2147752884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vatet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 00 00 80 68 ?? ?? ?? 00 [0-5] ff 15 ?? ?? ?? 00 [0-3] 6a 00 [0-5] ff 15 ?? ?? ?? 00 [0-19] 6a 00 6a 00 68 00 00 04 00 [0-16] ff 15 ?? ?? ?? 00 [0-9] 6a 00 [0-7] ff 15 ?? ?? ?? 00 [0-10] 6a 00 [0-10] 8d [0-3] 50 [0-19] ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 00 6a 00 6a 00 [0-4] 6a 00 6a 00 ff 15 ?? ?? ?? 00 6a ?? ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4e 00 6f 00 74 00 65 00 70 00 61 00 64 00 [0-48] 25 00 6c 00 64 00 [0-48] 45 00 44 00 49 00 54 00 [0-112] 63 00 6f 00 6d 00 6d 00 64 00 6c 00 67 00 5f 00 46 00 69 00 6e 00 64 00 52 00 65 00 70 00 6c 00 61 00 63 00 65 00}  //weight: 2, accuracy: Low
        $x_2_4 = {2e 64 61 74 00 5c 5c [0-9] 2e [0-9] 2e [0-9] 2e [0-9] 5c [0-144] 5c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vatet_SZS_2147755408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vatet.SZS"
        threat_id = "2147755408"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vatet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "RAINMETER.DLL" ascii //weight: 10
        $x_10_2 = "Software\\Rainmeter" ascii //weight: 10
        $x_10_3 = "Rainmeter desktop customization tool" ascii //weight: 10
        $x_10_4 = {40 3b c3 72 04 00 80 ?? ?? fe}  //weight: 10, accuracy: Low
        $x_1_5 = {5c 5c 31 30 2e [0-3] 2e [0-3] 2e [0-3] 5c}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 5c 31 37 32 2e [0-3] 2e [0-3] 2e [0-3] 5c}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 5c 31 39 32 2e 31 36 38 2e [0-3] 2e [0-3] 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Vatet_ZZ_2147760241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vatet.ZZ!dha"
        threat_id = "2147760241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vatet"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 00 80 68 ?? ?? ?? ?? ff 15 [0-144] 80 34 ?? fe 40 3b ?? 72 f7}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 00 00 80 68 [0-12] ff 15 [0-144] 80 34 ?? fa 40 3b ?? 72 f7}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 00 00 80 68 [0-12] ff 15 [0-144] 8a [0-52] ?? 2c ?? 88 ?? ?? ?? 3b ?? 72 f1 [0-32] 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {68 00 00 00 80 68 [0-12] ff 15 [0-144] 8a [0-52] ?? 2c ?? 34 ?? 88 ?? ?? ?? 3b ?? 72}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 00 00 80 68 [0-12] ff 15 [0-144] 8a ?? ?? [0-2] 34 ?? [0-2] 34 ?? 88 ?? ?? ?? 3b ?? 72}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 00 00 80 68 [0-32] ff 15 [0-176] 88 ?? ?? ?? 3b ?? 72 50 00 8a [0-4] 34 ?? ?? ?? 34 ?? ?? ?? 34 ?? ?? ?? 34 ?? ?? ?? 34}  //weight: 1, accuracy: Low
        $x_1_7 = {68 00 00 00 80 68 [0-32] ff 15 [0-254] 88 [0-9] 3b ?? 72 8a [0-4] (32|34) ?? ?? ?? (32|34) ?? ?? ?? (32|34)}  //weight: 1, accuracy: Low
        $x_1_8 = {68 00 00 00 80 68 [0-32] ff 15 80 01 88 [0-9] 3b ?? 72 8a [0-4] (32|34) ?? ?? ?? (32|34) ?? ?? ?? (32|34)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Vatet_ZA_2147760388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vatet.ZA!dha"
        threat_id = "2147760388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vatet"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 00 00 10 ?? ff 15 ?? ?? ?? ?? 8b ?? 83 ?? ff [0-6] 6a 00 6a 00 6a 00 6a 04 6a 00 ?? ff 15 08 01 0f 10 ?? ?? 66 0f f8 ?? 66 0f ef ?? 66 0f f8 ?? 0f 11 ?? ?? 83 ?? 10 3b ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vatet_2147772456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vatet!MTB"
        threat_id = "2147772456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vatet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 39 2c 68 34 32 2c 12 34 32 2c 12 34 32 2c 12 34 32 04 44 34 32 2c 68 34 32 2c 56 34 32 04 44 34 32 2c 68 34 32 04 44 34 32 04 44 34 32 04 44 34 32 2c 12 34 32 2c 12 34 32 2c 12 34 32 88 04 39 41 3b ca 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Vatet_SZ_2147788067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vatet.SZ"
        threat_id = "2147788067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vatet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {74 02 eb ea ?? ff ?? e8 d4 ff ff ff 22 00 eb 27 ?? 8b ?? 83 ?? 04 8b ?? 31 ?? 83 ?? 04 ?? 8b ?? 31 ?? 89 ?? 31 ?? 83 ?? 04 83 ?? 04 31}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

