rule Trojan_Win64_Redline_RAN_2147851707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.RAN!MTB"
        threat_id = "2147851707"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 00 89 85 98 00 00 00 48 8b 45 48 48 8b 8d c8 00 00 00 48 03 c8 48 8b c1 0f b6 00 88 85 9c 00 00 00 0f b6 85 9c 00 00 00 33 85 98 00 00 00 48 8b 4d ?? 48 8b 95 c8 00 00 00 48 03 d1 48 8b ca 88 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redline_GIL_2147852229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.GIL!MTB"
        threat_id = "2147852229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 00 89 44 24 68 48 8b 44 24 40 48 8b 8c 24 98 00 00 00 48 03 c8 48 8b c1 0f b6 00 88 44 24 24 0f b6 44 24 24 33 44 24 68 48 8b 4c 24 40 48 8b 94 24 98 00 00 00 48 03 d1 48 8b ca 88 01 e9 98 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redline_YT_2147853095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.YT!MTB"
        threat_id = "2147853095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 4e 10 41 0a c4 41 0f bc c1 66 0f ab f8 41 0f b6 46 0f 66 44 3b dd 30 04 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redline_YAB_2147890464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.YAB!MTB"
        threat_id = "2147890464"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 43 40 66 f7 e9 4e c1 e9 34 81 f1 ?? ?? ?? ?? 66 8b fe ba 20 00 00 00 4f 2b c3 66 4e 66 33 f3 4a 66 49 66 42 66 c1 df ?? c1 ca 9d 66 23 ce 66 b8 f3}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 0c 69 f6 ?? ?? ?? ?? 83 c7 04 8b c1 c1 e8 18 33 c1 69 c0 ?? ?? ?? ?? 33 f0 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Redline_GMK_2147891850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.GMK!MTB"
        threat_id = "2147891850"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {34 40 00 ff 34 40 ?? ?? bc 97 44 7a f1 bf 58 3a b0 f6 20 6b b0 fe 80 56 b0 5b 94}  //weight: 10, accuracy: Low
        $x_1_2 = "Xbjs42hs4z" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redline_MB_2147892669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.MB!MTB"
        threat_id = "2147892669"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f7 f9 8b c2 48 63 8d 80 02 00 00 48 8b 95 78 02 00 00 89 04 8a eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redline_MAA_2147917644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.MAA!MTB"
        threat_id = "2147917644"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 98 0f b6 44 05 ?? 48 63 8d ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 0f b6 0c 0a 33 c8 8b c1 48 63 8d ?? ?? ?? ?? 48 8b 95 ?? ?? ?? ?? 88 04 0a e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redline_GNK_2147917661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.GNK!MTB"
        threat_id = "2147917661"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c1 66 89 44 24 4e 69 c0 ?? ?? ?? ?? 48 ff c3 2b c1 88 44 1c 4f 48 83 fb 08}  //weight: 10, accuracy: Low
        $x_1_2 = "schtasks /create /tn \"SystemServicesTools\" /tr" ascii //weight: 1
        $x_1_3 = {31 00 37 00 36 00 2e 00 31 00 31 00 31 00 2e 00 31 00 37 00 34 00 2e 00 31 00 34 00 30 00 2f 00 61 00 70 00 69 00 2f 00 75 00 70 00 64 00 61 00 74 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redline_GXL_2147917924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.GXL!MTB"
        threat_id = "2147917924"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 83 ec 28 48 8b 0d ?? ?? ?? ?? ba fe 05 00 00 ff 15 ?? ?? ?? ?? 83 3d 9b 41 ?? ?? 00 48 8b 0d ?? ?? ?? ?? 74}  //weight: 5, accuracy: Low
        $x_5_2 = {43 0f b6 14 11 41 8a c1 83 e0 0f 0f b6 0c 18 32 ca 43 88 0c 11 4d 85 c9 74 07 41 32 cb 43 88 0c 11 44 0f b6 da 49 83 c1 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redline_ARD_2147928398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.ARD!MTB"
        threat_id = "2147928398"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 54 24 10 48 89 4c 24 08 48 83 ec 38 48 8b 4c 24 40 ff 15 ?? ?? ?? ?? 48 89 44 24 28 48 8b 54 24 48 48 8b 4c 24 28 ff 15 ?? ?? ?? ?? 48 89 44 24 20 48 8b 44 24 20 48 83 c4 38 c3}  //weight: 2, accuracy: Low
        $x_1_2 = {48 8b 94 24 80 02 00 00 48 8d 4c 24 4c ff 15 ?? ?? ?? ?? 85 c0 75 43 44 8b 44 24 28 33 d2 b9 01 00 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redline_SIM_2147935242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.SIM!MTB"
        threat_id = "2147935242"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 50 00 00 00 8d 4a d0 e8 06 95 ff ff 4c 8b d8 48 85 c0 75 08 83 c8 ff e9 a2 02 00 00 48 89 05 1f 6d 1f 00 b9 20 00 00 00 89 0d 04 6d 1f 00 48 05 00 0a 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Redline_GZZ_2147941181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Redline.GZZ!MTB"
        threat_id = "2147941181"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Redline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {64 21 21 00 00 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 00 00 00 00 53 48 47 65 74 46 6f 6c 64 65}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

