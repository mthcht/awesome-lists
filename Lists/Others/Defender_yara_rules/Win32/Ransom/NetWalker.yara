rule Ransom_Win32_NetWalker_S_2147751635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NetWalker.S!MTB"
        threat_id = "2147751635"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWalker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 55 57 c7 44 ?? ?? 5c 00 76 00 c7 44 ?? ?? 73 00 73 00 c7 44 ?? ?? 61 00 64 00 c7 44 ?? ?? 6d 00 69 00 c7 44 ?? ?? 6e 00 2e 00 c7 44 ?? ?? 65 00 78 00 c7 44 ?? ?? 65 00 00 00 c7 44 ?? ?? 20 00 64 00 c7 44 ?? ?? 65 00 6c 00 c7 44 ?? ?? 65 00 74 00 c7 44 ?? ?? 65 00 20 00 c7 44 ?? ?? 73 00 68 00 c7 44 ?? ?? 61 00 64 00 c7 44 ?? ?? 6f 00 77 00 c7 44 ?? ?? 73 00 20 00 c7 44 ?? ?? 2f 00 61 00 c7 44 ?? ?? 6c 00 6c 00 c7 44 ?? ?? 20 00 2f 00 c7 44 ?? ?? 71 00 75 00 c7 44 ?? ?? 69 00 65 00 c7 44 ?? ?? 74 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_NetWalker_GS_2147754253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NetWalker.GS!MTB"
        threat_id = "2147754253"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWalker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4e 65 74 77 61 6c 6b 65 72 5f 64 6c 6c 2e 64 6c 6c 00 44 6f}  //weight: 2, accuracy: High
        $x_1_2 = "code_id:" ascii //weight: 1
        $x_1_3 = "onion1" ascii //weight: 1
        $x_1_4 = "onion2" ascii //weight: 1
        $x_1_5 = "namesz" ascii //weight: 1
        $x_1_6 = "unlock" ascii //weight: 1
        $x_1_7 = "pspath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_NetWalker_MX_2147755326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NetWalker.MX!MTB"
        threat_id = "2147755326"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWalker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "expand 32-byte kexpand 16-byte k" ascii //weight: 1
        $x_1_2 = "unlock" ascii //weight: 1
        $x_1_3 = "pspath" ascii //weight: 1
        $x_1_4 = "mpr.dll" ascii //weight: 1
        $x_1_5 = "eventvwr.exe" ascii //weight: 1
        $x_1_6 = "mscfile" ascii //weight: 1
        $x_1_7 = "slui.exe" ascii //weight: 1
        $x_1_8 = "exefile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_NetWalker_2147763406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NetWalker!MTB"
        threat_id = "2147763406"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWalker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c2 03 c8 0f b6 c1 8b 4c 24 ?? 0f b6 04 ?? 30 04 0e 46 8b 4c 24 ?? 3b f5 72 c0 00 8d ?? 01 0f b6 ?? 8a 14 ?? 0f b6 c2 03 c1 0f b6 c8 89 4c 24 1c 0f b6 04 ?? 88 04 ?? 88 14 ?? 0f b6 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_NetWalker_2147763406_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NetWalker!MTB"
        threat_id = "2147763406"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWalker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "expand 32-byte kexpand 16-byte k" ascii //weight: 1
        $x_1_2 = "nstopmarker" wide //weight: 1
        $x_1_3 = "The network is locked" ascii //weight: 1
        $x_1_4 = "If you do not pay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_NetWalker_STA_2147766287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NetWalker.STA"
        threat_id = "2147766287"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWalker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "expand 32-byte kexpand 16-byte k" ascii //weight: 3
        $x_3_2 = "Your files are encrypted" ascii //weight: 3
        $x_3_3 = {20 25 64 0d 66 c7 44 ?? ?? 0a 00 c7 44 ?? ?? 64 65 6c 20 c7 44 ?? ?? 22 25 77 73 c7 44 ?? ?? 22 0d 0a 00 c7 44 ?? ?? 64 65 6c 20 c7 44 ?? ?? 25 25 30 0d 66 c7 44 ?? ?? 0a 00}  //weight: 3, accuracy: Low
        $x_3_4 = {6f 00 74 00 c7 44 ?? ?? 65 00 70 00 c7 44 ?? ?? 61 00 64 00 c7 44 ?? ?? 2e 00 65 00 c7 44 ?? ?? 78 00 65 00}  //weight: 3, accuracy: Low
        $x_3_5 = {7b 6f 6e 69 c7 44 ?? ?? 6f 6e 31 7d c6 44 ?? ?? 00 c7 44 ?? ?? 7b 6f 6e 69 c7 44 ?? ?? 6f 6e 32 7d c6 44 ?? ?? 00 c7 44 ?? ?? 7b 63 6f 64}  //weight: 3, accuracy: Low
        $x_5_6 = {0f b6 c2 03 c8 0f b6 c1 8b 4c 24 ?? 0f b6 04 ?? 30 04 0e 46 8b 4c 24 ?? 3b f5 72 c0 00 8d ?? 01 0f b6 ?? 8a 14 ?? 0f b6 c2 03 c1 0f b6 c8 89 4c 24 1c 0f b6 04 ?? 88 04 ?? 88 14 ?? 0f b6 0c}  //weight: 5, accuracy: Low
        $x_5_7 = {5c 00 76 00 c7 44 ?? ?? 73 00 73 00 c7 44 ?? ?? 61 00 64 00 c7 44 ?? ?? 6d 00 69 00 c7 44 ?? ?? 6e 00 2e 00 c7 44 ?? ?? 65 00 78 00 c7 44 ?? ?? 65 00 00 00 c7 44 ?? ?? 20 00 64 00 c7 44 ?? ?? 65 00 6c 00 c7 44 ?? ?? 65 00 74 00 c7 44 ?? ?? 65 00 20 00 c7 44 ?? ?? 73 00 68 00 c7 44 ?? ?? 61 00 64 00 c7 44 ?? ?? 6f 00 77 00 c7 44 ?? ?? 73 00 20 00 c7 44 ?? ?? 2f 00 61 00 c7 44 ?? ?? 6c 00 6c 00 c7 44 ?? ?? 20 00 2f 00 c7 44 ?? ?? 71 00 75 00 c7 44 ?? ?? 69 00 65 00 c7 44 ?? ?? 74 00 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_NetWalker_STA_2147767632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NetWalker.STA!!NetWalker.STE"
        threat_id = "2147767632"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWalker"
        severity = "Critical"
        info = "NetWalker: an internal category used to refer to some threats"
        info = "STE: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "expand 32-byte kexpand 16-byte k" ascii //weight: 3
        $x_3_2 = "Your files are encrypted" ascii //weight: 3
        $x_3_3 = {20 25 64 0d 66 c7 44 ?? ?? 0a 00 c7 44 ?? ?? 64 65 6c 20 c7 44 ?? ?? 22 25 77 73 c7 44 ?? ?? 22 0d 0a 00 c7 44 ?? ?? 64 65 6c 20 c7 44 ?? ?? 25 25 30 0d 66 c7 44 ?? ?? 0a 00}  //weight: 3, accuracy: Low
        $x_3_4 = {6f 00 74 00 c7 44 ?? ?? 65 00 70 00 c7 44 ?? ?? 61 00 64 00 c7 44 ?? ?? 2e 00 65 00 c7 44 ?? ?? 78 00 65 00}  //weight: 3, accuracy: Low
        $x_3_5 = {7b 6f 6e 69 c7 44 ?? ?? 6f 6e 31 7d c6 44 ?? ?? 00 c7 44 ?? ?? 7b 6f 6e 69 c7 44 ?? ?? 6f 6e 32 7d c6 44 ?? ?? 00 c7 44 ?? ?? 7b 63 6f 64}  //weight: 3, accuracy: Low
        $x_5_6 = {0f b6 c2 03 c8 0f b6 c1 8b 4c 24 ?? 0f b6 04 ?? 30 04 0e 46 8b 4c 24 ?? 3b f5 72 c0 00 8d ?? 01 0f b6 ?? 8a 14 ?? 0f b6 c2 03 c1 0f b6 c8 89 4c 24 1c 0f b6 04 ?? 88 04 ?? 88 14 ?? 0f b6 0c}  //weight: 5, accuracy: Low
        $x_5_7 = {5c 00 76 00 c7 44 ?? ?? 73 00 73 00 c7 44 ?? ?? 61 00 64 00 c7 44 ?? ?? 6d 00 69 00 c7 44 ?? ?? 6e 00 2e 00 c7 44 ?? ?? 65 00 78 00 c7 44 ?? ?? 65 00 00 00 c7 44 ?? ?? 20 00 64 00 c7 44 ?? ?? 65 00 6c 00 c7 44 ?? ?? 65 00 74 00 c7 44 ?? ?? 65 00 20 00 c7 44 ?? ?? 73 00 68 00 c7 44 ?? ?? 61 00 64 00 c7 44 ?? ?? 6f 00 77 00 c7 44 ?? ?? 73 00 20 00 c7 44 ?? ?? 2f 00 61 00 c7 44 ?? ?? 6c 00 6c 00 c7 44 ?? ?? 20 00 2f 00 c7 44 ?? ?? 71 00 75 00 c7 44 ?? ?? 69 00 65 00 c7 44 ?? ?? 74 00 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

