rule VirTool_Win64_Amsipatch_B_2147835315_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Amsipatch.B!MTB"
        threat_id = "2147835315"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Amsipatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 39 44 31 52 4b 75 3a}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 bf 00 00 00 00 48 83 c3 0a 48 89 44 24 20 41 b9 04 00 00 00 48 c7 45 b7 00 10 00 00 4c 8d ?? ?? 48 89 5d c7 48 8d ?? ?? 48 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 44 24 20 00 00 00 00 4c 8d ?? ?? 48 8b d3 48 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {44 8b 4d bf 48 8d ?? ?? 4c 8d ?? ?? 48 89 44 24 20 48 8d ?? ?? 48 8b cf ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Amsipatch_C_2147835316_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Amsipatch.C!MTB"
        threat_id = "2147835316"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Amsipatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 01 44 31 52 4b 90 90}  //weight: 1, accuracy: High
        $x_1_2 = {41 b9 04 00 00 00 48 89 44 24 20 4c 8d ?? ?? 48 c7 45 c7 00 10 00 00 48 8d ?? ?? 48 89 5d b7 48 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 44 24 20 00 00 00 00 4c 8d ?? ?? 48 8b d3 48 8b cf ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {44 8b 4d bf 48 8d ?? ?? 4c 8d ?? ?? 48 89 44 24 20 48 8d ?? ?? 48 8b cf ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Amsipatch_D_2147835317_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Amsipatch.D!MTB"
        threat_id = "2147835317"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Amsipatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 c0 90 90}  //weight: 1, accuracy: High
        $x_1_2 = {41 b9 04 00 00 00 48 89 44 24 20 4c 8d ?? ?? ?? 48 c7 44 24 40 00 10 00 00 48 8d ?? ?? ?? 48 89 5c 24 30 48 8b ce ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {48 c7 44 24 20 00 00 00 00 4c 8d ?? ?? ?? 48 8b d3 48 8b ce ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {44 8b 4c 24 38 48 8d ?? ?? ?? 4c 8d ?? ?? ?? 48 89 44 24 20 48 8d ?? ?? ?? 48 8b ce ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

