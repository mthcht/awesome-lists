rule Ransom_Win32_Chaos_NIT_2147929717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Chaos.NIT!MTB"
        threat_id = "2147929717"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 20 8b 01 8b 15 38 b3 92 00 89 10 8b 01 89 44 24 28 8d 1d 38 b3 92 00 89 1c 24 89 54 24 04 89 44 24 08 e8 9d 5f ff ff 0f b6 44 24 0c 84 c0 74 cd}  //weight: 2, accuracy: High
        $x_2_2 = {66 0f 6e 44 24 08 66 0f c4 c3 04 f3 0f 70 c0 00 66 0f 6f c8 66 0f ef 05 e0 b6 92 00 66 0f 38 dc c0 83 fb 10}  //weight: 2, accuracy: High
        $x_1_3 = {89 44 24 04 e8 f8 f9 ff ff 83 7c 24 08 ff 0f 84 86 01 00 00 8b 44 24 24 8b 0d 50 d1 8c 00 8b 94 24 10 03 00 00 89 0c 24 89 44 24 04 89 54 24 08 e8 1c fa ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Chaos_CCJU_2147935360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Chaos.CCJU!MTB"
        threat_id = "2147935360"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 04 32 33 d2 88 46 01 8b 44 24 24 03 c6 f7 74 24 10 0f b6 82 ?? ?? ?? ?? 8b 54 24 28 32 04 32 88 46 02 83 c6 05 8d 04 37}  //weight: 2, accuracy: Low
        $x_1_2 = ".chaos" wide //weight: 1
        $x_1_3 = "encrypt_step" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Chaos_C_2147935687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Chaos.C"
        threat_id = "2147935687"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 00 6b 00 65 00 79 00 00 00 00 00 70 00 61 00 74 00 68 00 00 00 00 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 5f 00 73 00 74 00 65 00 70 00 00 00 00 00 77 00 6f 00 72 00 6b 00 5f 00 6d 00 6f 00 64 00 65 00 00 00 6c 00 6f 00 63 00 61 00 6c 00 5f 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 00 00 6c 00 6f 00 63 00 61 00 6c 00 00 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 00 00 69 00 67 00 6e 00 6f 00 72 00 61 00 72 00 5f 00 61 00 72 00 71 00 75 00 69 00 76 00 6f 00 73 00 5f 00 67 00 72 00 61 00 6e 00 64 00 65 00 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 63 00 68 ?? 61 00 6f 00 73 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Chaos_AMX_2147947328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Chaos.AMX!MTB"
        threat_id = "2147947328"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Chaos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted" wide //weight: 1
        $x_1_2 = "CHAOS RANSOMWARE" wide //weight: 1
        $x_1_3 = "recover your files" wide //weight: 1
        $x_1_4 = "ransom in Bitcoin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

