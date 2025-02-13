rule Trojan_Win64_Gozi_RE_2147832073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gozi.RE!MTB"
        threat_id = "2147832073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b c5 ba 00 10 00 00 41 b9 01 00 00 00 44 2b c6 49 8b cf 41 81 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 43 0c ff c6 2b 43 08 49 81 c7 00 10 00 00 03 43 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Gozi_RE_2147832073_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gozi.RE!MTB"
        threat_id = "2147832073"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 8b c5 ba 00 10 00 00 41 b9 01 00 00 00 44 2b c6 49 8b cf 41 81 e8 13 c8 47 7e e8 ?? ?? ?? ?? 8b 43 0c ff c6 2b 43 08 49 81 c7 00 10 00 00 03 43 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Gozi_RF_2147836214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gozi.RF!MTB"
        threat_id = "2147836214"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 89 11 48 83 c3 02 48 83 c1 02 66 41 3b d2 75 bb 49 3b fa 74 0a 48 2b c8 48 d1 f9 ff c9 89 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Gozi_RI_2147847402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gozi.RI!MTB"
        threat_id = "2147847402"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 02 41 b9 5f f3 6e 3c 69 c0 0d 66 19 00 05 5f f3 6e 3c 89 01 69 c0 0d 66 19 00 44 8d 80 5f f3 6e 3c 66 44 89 41 04 45 69 c0 0d 66 19 00 45 03 c1 48 83 c1 08 66 44 89 41 fe 44 89 02 41 b8 08 00 00 00 8b 02 69 c0 0d 66 19 00 41 03 c1 88 01 48 83 c1 01 49 83 e8 01 89 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Gozi_MKV_2147848430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gozi.MKV!MTB"
        threat_id = "2147848430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ff 41 89 cb 42 8d 04 0a 8b 15 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 45 0f af d9 44 0f af 1d ?? ?? ?? ?? 0f af d1 0f af 0d ?? ?? ?? ?? 29 d0 48 8d 15 99 39 00 00 0f af 0d ?? ?? ?? ?? 44 29 d8 41 0f af c9 44 0f af 0d 87 29 00 00 01 c8 44 29 c8 2b 05 ?? ?? ?? ?? 48 98 8a 04 02 48 8b 54 24 ?? 42 32 04 12 42 88 04 16 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Gozi_RZ_2147851956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gozi.RZ!MTB"
        threat_id = "2147851956"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 57 f0 0f 57 f8 0f 28 de 0f 28 cf 41 0f 14 cb 44 0f 57 c0 0f 57 e8 0f 57 e0 41 0f 14 d8 41 0f 28 c3 0f 14 d9 0f 14 d4 0f 28 cd 0f 14 c8 0f 29 58 d0}  //weight: 1, accuracy: High
        $x_1_2 = "PhysX3_x64.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Gozi_DK_2147892470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Gozi.DK!MTB"
        threat_id = "2147892470"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Gozi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 29 d8 4d 63 c0 42 8a 04 00 42 32 04 0a 42 88 04 09 49 ff c1 e9}  //weight: 1, accuracy: High
        $x_1_2 = "Z6^#w)TXiHCXOg7DpNxRBDY4>yYCs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

