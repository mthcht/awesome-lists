rule VirTool_Win64_Cookidumpesz_2147921764_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cookidumpesz!MTB"
        threat_id = "2147921764"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cookidumpesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 18 00 00 00 ?? ?? ?? ?? ?? 48 8b da 48 8b f9 ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b d3 [0-20] 48 8b 54 24 30 48 85 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 54 24 38 [0-18] 41 b8 08 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b 4c 24 38 [0-16] 48 89 44 24 20 41 b9 08 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 8b d3 [0-16] 85 c0 [0-20] 48 8b 54 24 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Cookidumpesz_B_2147924964_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cookidumpesz.B!MTB"
        threat_id = "2147924964"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cookidumpesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b f0 41 b9 18 00 00 00 ?? ?? ?? ?? ?? 48 8b da 48 8b f9 ?? ?? ?? ?? ?? 85 c0 ?? ?? 48 8b d3 [0-20] 48 8b 54 24 30 48 85 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 54 24 70 [0-18] 49 8b fe 4c 39 74 24 70 ?? ?? 48 8b 1c fe 48 85 db [0-24] 45 8b c5 [0-19] 48 ff c7 48 3b 7c 24 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Cookidumpesz_D_2147966877_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cookidumpesz.D"
        threat_id = "2147966877"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cookidumpesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b f0 4c 89 64 24 70 48 85 c0 ?? ?? ?? ?? ?? ?? ?? 48 89 44 24 20 4c 8b ce 41 b8 98 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 ?? ?? 48 8b 54 24 70}  //weight: 1, accuracy: Low
        $x_1_2 = {49 8b fc 4c 39 64 24 70 ?? ?? 48 8b 1c fe 48 85 db [0-19] e8 ?? ?? ?? ?? 45 8b c5 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 ff c7 48 3b 7c 24 70}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 54 24 68 84 d2 ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 85 db [0-17] 48 8b d3 ?? ?? ?? ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

