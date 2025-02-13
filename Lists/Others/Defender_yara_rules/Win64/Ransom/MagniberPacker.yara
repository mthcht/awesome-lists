rule Ransom_Win64_MagniberPacker_AO_2147845458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.AO!MTB"
        threat_id = "2147845458"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ff c6 e9 05 00 48 ff c6 48 ff c7 48 ff c2 48 81 fa ?? ?? ?? ?? 8a ae ?? ?? ?? ?? 32 ae ?? ?? ?? ?? 32 e8 8a c5 88 2f 48 ff c6}  //weight: 1, accuracy: Low
        $x_1_2 = {48 ff c6 eb 05 00 48 ff c6 48 ff c7 48 ff c2 48 81 fa ?? ?? ?? ?? 8a ae ?? ?? ?? ?? 32 ae ?? ?? ?? ?? 32 e8 8a c5 88 2f 48 ff c6}  //weight: 1, accuracy: Low
        $x_1_3 = {48 ff c6 e9 05 00 48 ff c6 48 ff c7 48 ff c2 48 81 fa ?? ?? ?? ?? 8a ae ?? ?? ?? ?? 32 ae ?? ?? ?? ?? 32 ec 8a e5 88 2f 48 ff c6}  //weight: 1, accuracy: Low
        $x_1_4 = {48 ff c6 eb 05 00 48 ff c6 48 ff c7 48 ff c2 48 81 fa ?? ?? ?? ?? 8a ae ?? ?? ?? ?? 32 ae ?? ?? ?? ?? 32 ec 8a e5 88 2f 48 ff c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win64_MagniberPacker_SA_2147846043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SA!MTB"
        threat_id = "2147846043"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8c 10 88 50 ab 02 1f be ?? ?? ?? ?? 02 53 ?? ed 69 24 ab ?? ?? ?? ?? e7 ?? b5 ?? 30 52 ?? 38 1e 31 67 ?? 7e ?? d1 c8 b4 ?? ef b6 ?? fa b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SB_2147846044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SB!MTB"
        threat_id = "2147846044"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a0 74 46 02 4c a1 65 8a fa 4c f2 8d 66 ?? 68 ?? ?? ?? ?? cd ?? 6a ?? ba ?? ?? ?? ?? 85 29 80 a0 ?? ?? ?? ?? ?? c9 33 89 ?? ?? ?? ?? e1 ?? 34 ?? 13 e1 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SC_2147846225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SC!MTB"
        threat_id = "2147846225"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 03 dd e9 bc ?? ?? ?? ?? ?? ?? ?? e3 23 88 ?? ?? ?? ?? 03 6d ?? 7b ?? c3 32 ae ?? ?? ?? ?? e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? fb 04 ?? 94 6a ?? 31 b0 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SE_2147846482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SE!MTB"
        threat_id = "2147846482"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 4b eb 25 cf 32 9d ?? ?? ?? ?? ?? 15 ?? ?? ?? ?? 31 0a f7 3f 22 61 ?? dc 5e ?? 10 9c d8 ?? ?? ?? ?? 02 85 ?? ?? ?? ?? 2b 23 a2}  //weight: 1, accuracy: Low
        $x_1_2 = "BMwUWhyTqhws" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SF_2147846919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SF!MTB"
        threat_id = "2147846919"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e2 41 b1 ?? 66 64 81 5d ?? ?? ?? bc ?? ?? ?? ?? a8 ?? 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? ?? ?? ?? ?? ed 84 18 2d ?? ?? ?? ?? 30 52 ?? 38 1e 31 67 ?? 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SG_2147846931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SG!MTB"
        threat_id = "2147846931"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 71 8d 93 ?? ?? ?? ?? e5 ?? 19 db 0d ?? ?? ?? ?? 35 ?? ?? ?? ?? a5 4b e1 ?? ae de 72 ?? 6c ba ?? ?? ?? ?? 80 8d ?? ?? ?? ?? ?? ?? ?? 5d e9 ?? ?? ?? ?? b4 fe 31 ae ?? ?? ?? ?? ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SH_2147847171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SH!MTB"
        threat_id = "2147847171"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 c9 98 3c 7c 2b 6e ?? 3b 39 24 ?? a3 ?? ?? ?? ?? ?? ?? ?? ?? ae 8e 96 ?? ?? ?? ?? 31 ac 97 ?? ?? ?? ?? 73 ?? a9 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SI_2147847323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SI!MTB"
        threat_id = "2147847323"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 4a 3e 2b 01 f7 91 ?? ?? ?? ?? bd ?? ?? ?? ?? ec b9 ?? ?? ?? ?? 36 38 27}  //weight: 1, accuracy: Low
        $x_1_2 = {91 81 f9 53 5d bd 4e d1 2f b4 ?? 66 29 1f e7 ?? ae 8c ae ?? ?? ?? ?? 32 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SJ_2147847566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SJ!MTB"
        threat_id = "2147847566"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 d0 3a a0 ?? ?? ?? ?? 35 ?? ?? ?? ?? 76 ?? 15 ?? ?? ?? ?? 76 ?? a2 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? ?? ?? ?? ?? 70 ?? ef 65 a0 ?? ?? ?? ?? ?? ?? ?? ?? 12 54 01 ?? 6b 8a ?? ?? ?? ?? ?? 9d 32 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SK_2147847966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SK!MTB"
        threat_id = "2147847966"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 3c 57 4b 15 ?? ?? ?? ?? 66 98 1b 6c 6c ?? 0b 5b ?? b4 ?? 41 6d 33 18 18 5f ?? 55 d3 c4 31 f0 3a 57}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SL_2147848052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SL!MTB"
        threat_id = "2147848052"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f2 b1 f7 7c ?? 4c 87 e4 eb ?? 66 c9 33 89 ?? ?? ?? ?? e1 ?? 34 ?? 13 e1 79 ?? 4c 8b d1 eb ?? d1 05 ?? ?? ?? ?? da 2c 2d ?? ?? ?? ?? 74 ?? 02 2e 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SM_2147848672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SM!MTB"
        threat_id = "2147848672"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1a 32 b6 36 18 17 c3 4f 1b 53 ?? 4c fa de 3c 13 32 56 ?? 36 45}  //weight: 1, accuracy: Low
        $x_1_2 = {32 08 5e f2 e6 ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_MagniberPacker_SD_2147902116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/MagniberPacker.SD!MTB"
        threat_id = "2147902116"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "MagniberPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 ae a0 0d 00 00 e9 ?? ?? ?? ?? a0 ?? ?? ?? ?? ?? ?? ?? ?? 96 bc ?? ?? ?? ?? d2 eb 76 ?? 7a ?? 94 e5 ?? eb ?? 05 aa 48 81 fa 94 01 01 00 eb e9 ?? ?? ?? ?? a2 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

