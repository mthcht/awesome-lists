rule Trojan_Win64_Kimsuky_A_2147847017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kimsuky.A!MTB"
        threat_id = "2147847017"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kimsuky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 8b c2 80 ea ?? 41 8b c0 83 c8 20 80 fa ?? 41 0f 47 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Kimsuky_B_2147899196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kimsuky.B!MTB"
        threat_id = "2147899196"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kimsuky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {44 0f b7 4c 6c ?? 66 44 33 0c 70 48 8b 4f 10 48 8b 57 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Kimsuky_AH_2147911308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kimsuky.AH!MTB"
        threat_id = "2147911308"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kimsuky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 44 24 58 c6 44 24 30 aa c6 44 24 31 bb c6 44 24 32 34 c6 44 24 33 23 c6 44 24 34 a4 c6 44 24 35 c4 c6 44 24 36 c7 c6 44 24 37 dd c6 44 24 38 23 c6 44 24 39 53 c6 44 24 3a ea c6 44 24 3b a2 c6 44 24 3c 75 c6 44 24 3d 82 c6 44 24 3e e7 c6 44 24 3f 3e}  //weight: 2, accuracy: High
        $x_2_2 = {c6 44 24 46 82 c6 44 24 47 a4 c6 44 24 48 dd c6 44 24 49 1a c6 44 24 4a 3d c6 44 24 4b c2 c6 44 24 4c d2 c6 44 24 4d 62 c6 44 24 4e 28 c6 44 24 4f be c6 44 24 20 1a c6 44 24 21 b5 c6 44 24 22 3a c6 44 24 23 bb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Kimsuky_ARA_2147919884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kimsuky.ARA!MTB"
        threat_id = "2147919884"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kimsuky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "nidlogin.apollo-page." wide //weight: 4
        $x_4_2 = "nid.apollo-blue7.kro.kr" wide //weight: 4
        $x_3_3 = "/cmd/index.php?_idx_=7" wide //weight: 3
        $x_3_4 = "/database/index.php?_apo_=27" wide //weight: 3
        $x_2_5 = "Remote Desktop Users" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Kimsuky_SEC_2147954221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kimsuky.SEC!MTB"
        threat_id = "2147954221"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kimsuky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "termsadisd.dll" ascii //weight: 2
        $x_1_2 = {66 0f 6f 25 ?? ?? ?? ?? 4c 8d 4c 24 40 66 0f 6f 2d ?? ?? ?? ?? 33 f6 44 8b d6 44 8d 46 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

