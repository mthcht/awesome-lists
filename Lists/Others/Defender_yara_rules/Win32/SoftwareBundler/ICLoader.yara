rule SoftwareBundler_Win32_ICLoader_222548_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader"
        threat_id = "222548"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 39 4d 5a 0f 85 ?? ?? 00 00 8b 41 3c 68 00 01 00 00 03 c1 50 a3 ?? ?? ?? ?? ff d6 85 c0 0f 85 ?? ?? 00 00 a1 ?? ?? ?? ?? 66 81 38 50 45}  //weight: 1, accuracy: Low
        $x_1_2 = {75 0b 33 1a ff d3 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_222548_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader"
        threat_id = "222548"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 8a 45 0f d3 e3 33 db 0b 1d ?? ?? ?? ?? 03 d9 8a 0b 90 90 33 c1 88 03 90 42 81 fa 27 07 00 00 89 55 08 7e}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 69 00 74 00 63 00 68 00 65 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 61 00 76 00 61 00 74 00 61 00 72 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_E_249597_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.E"
        threat_id = "249597"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\http\\UserChoice\\ProgIdNHKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\regexp:.*\\DisplayName" wide //weight: 1
        $x_1_2 = "http://megadowl.com/terms-ru.html" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_I_251750_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.I!bit"
        threat_id = "251750"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 ce 0b 22 d6 30 26 61 8b 45 08 40 3d 44 07 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_BS_256606_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.BS!MTB"
        threat_id = "256606"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 6a 00 03 c7 6a 00 6a 00 6a 00 8a 10 6a 00 32 d1 88 10 ff d5 83 3d ?? ?? ?? ?? 02 76 01 43 81 fb 44 07 00 00 7e}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c3 03 c7 30 08 ff d5 83 3d ?? ?? ?? ?? 02 76 01 43 81 fb 44 07 00 00 7e}  //weight: 1, accuracy: Low
        $x_1_3 = {50 72 6f 63 c7 05 ?? ?? ?? ?? 65 73 73 33 c7 05 ?? ?? ?? ?? 32 46 69 72 66 c7 05 ?? ?? ?? ?? 73 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_BM_257372_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.BM!MTB"
        threat_id = "257372"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 c3 6a 00 6a 00 03 c7 6a 00 6a 00 8a 10 6a 00 6a 00 6a 00 32 d1 6a 00 6a 00 88 10 ff ?? 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 43 ff ?? 81 fb da 04 00 00 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_BN_258087_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.BN!MTB"
        threat_id = "258087"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 14 8a 11 88 15 ?? ?? ?? ?? 8b 45 14 83 c0 01 89 45 14 8b 4d 0c 89 4d f8 ba ?? ?? ?? ?? 03 55 08 8b 45 0c 03 45 08 8b 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8a 14 32 88 14 08 8b 45 08 0f be 88 ?? ?? ?? ?? 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_BO_258217_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.BO!MTB"
        threat_id = "258217"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ee 10 8a 0e bb ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 d9 03 c8 46 8a 1c 03 88 1c 39 8a 88 ?? ?? ?? ?? 84 c9 75 12 8b 0d ?? ?? ?? ?? 8a 1d ?? ?? ?? ?? 03 c8 03 cf 30 19 39 15 ?? ?? ?? ?? 7e 03 40 eb 01 cf 3d 7d 05 00 00 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_BP_258515_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.BP!MTB"
        threat_id = "258515"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d1 8d 34 01 8b 4d 0c 8a 14 02 88 14 0e 8a ?? ?? ?? ?? ?? 84 d2 75 ?? 8b 15 ?? ?? ?? ?? 03 d0 03 ca 8a 15 ?? ?? ?? ?? 30 11 83 3d ?? ?? ?? ?? 03 7e}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d9 03 c8 46 8a 1c 03 88 1c 39 8a 88 ?? ?? ?? ?? 84 c9 75 ?? 8b 0d ?? ?? ?? ?? 8a 1d ?? ?? ?? ?? 03 c8 03 cf 30 19 39 15 ?? ?? ?? ?? 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_BQ_258516_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.BQ!MTB"
        threat_id = "258516"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 03 c1 8a 0c 0a 8b 55 0c 88 0c 10 60 8d 05 ?? ?? ?? ?? c1 e0 05 61 8b 45 08 8a 88 ?? ?? ?? ?? 84 c9 75 ?? 60 8d 05 ?? ?? ?? ?? c1 e0 05 61 8b 0d ?? ?? ?? ?? 8b 55 08 8b 45 0c 03 ca 03 c1 8a 0d ?? ?? ?? ?? 30 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_BR_259094_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.BR!MTB"
        threat_id = "259094"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 8b 55 08 83 e2 0f 85 d2 75 ?? 8b 45 ?? 83 e8 10 89 45 ?? 60 8b ?? 83 ?? ?? 83 ?? ?? 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {61 8b 4d 14 8a 11 88 15 ?? ?? ?? ?? 8b 45 ?? 83 c0 01 89 45 ?? 60 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 08 83 c1 01 89 4d ?? eb ?? ff e1 81 7d ?? 04 05 00 00 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_BT_259890_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.BT!MTB"
        threat_id = "259890"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 46 8d 3c 10 8b 45 0c 8a 0c 11 88 0c 07 8a 8a ?? ?? ?? ?? 84 c9 75 ?? 8b 0d ?? ?? ?? ?? 03 ca 03 c1 8a 0d ?? ?? ?? ?? 30 08 83 3d ?? ?? ?? ?? 03 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_BU_260148_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.BU!MTB"
        threat_id = "260148"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 47 8d 34 10 8b 45 0c 8a 0c 11 88 0c 06 8a 8a ?? ?? ?? ?? 84 c9 75 ?? 8b 0d ?? ?? ?? ?? 03 ca 03 c1 8a 0d ?? ?? ?? ?? 30 08 83 3d ?? ?? ?? ?? 03 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_DSA_273834_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.DSA!MTB"
        threat_id = "273834"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 24 0c 53 8a 1c 08 32 da 88 1c 08 8b 0d ?? ?? ?? ?? 33 c0 5b 8a 41 01 8b 4c 24 08 0c 03 23 c1 c3 05 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_ICLoader_SE_279102_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/ICLoader.SE!MTB"
        threat_id = "279102"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 08 a1 ?? ?? ?? ?? 83 f8 ?? 76 ?? 8b 0d ?? ?? ?? ?? 8b 56 ?? 8b 3d ?? ?? ?? ?? 8a 1c 08 8a 14 3a 32 da 88 1c 08}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 8b 35 ?? ?? ?? ?? 8b 54 24 ?? 8a 14 0a 8a 1c 06 32 da 41 88 1c 06 40 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

