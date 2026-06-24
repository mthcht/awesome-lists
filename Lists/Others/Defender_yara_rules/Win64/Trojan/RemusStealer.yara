rule Trojan_Win64_RemusStealer_ARM_2147969220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RemusStealer.ARM!MTB"
        threat_id = "2147969220"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 04 24 48 89 4c 24 08 48 c7 44 24 10 00 00 00 00 48 c7 44 24 18 00 08 00 00 e8 ?? ?? ?? ?? 45 0f 57 ff 4c 8b 35 16 92 2e 00 65 4d 8b 36 4d 8b 36 48 8b 44 24 20 48 85 c0 0f 84 6e 01 00 00 48 89 44 24 28 48 8d 1d 10 25 14 00 b9 1d 00 00 00 48 89 cf e8}  //weight: 2, accuracy: Low
        $x_1_2 = {65 4d 8b 36 4d 8b 36 48 8b 44 24 20 0f 1f 40 00 48 85 c0 0f 84 05 02 00 00 48 8d 1d 4a ee 13 00 b9 0c 00 00 00 48 89 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RemusStealer_ARR_2147969504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RemusStealer.ARR!MTB"
        threat_id = "2147969504"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e2 08 0b d1 41 0f b6 4c 18 01 c1 e2 08 0b d1 41 0f b6 0c 18 c1 e2 08 0b d1 69 ca 89 35 14 7a 41 0f b6 54 18 07 c1 e2 08 2b f9 41 0f b6 4c 18 06 0b d1 c1 cf 13 41 0f b6 4c 18 05 c1 e2 08 0b d1 69 ff b1 79 37 9e 41 0f b6 4c 18 04 c1 e2 08 0b d1 69 ca 89 35 14 7a 41 0f b6 54 18 0b c1 e2 08 2b f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RemusStealer_AMR_2147970378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RemusStealer.AMR!MTB"
        threat_id = "2147970378"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 24 04 0f b6 c0 83 f0 13 88 44 24 04 0f b6 44 24 05 0f b6 c0 83 f0 13 88 44 24 05 0f b6 44 24 06 0f b6 c0 83 f0 13 88 44 24 06 0f b6 44 24 07 0f b6 c0 83 f0 13 88 44 24 07 b8 01 00 00 00 48 6b c0 00 48 8b 4c 24 18 0f b6 04 01 0f b6 4c 24 04 0f b6 c9 3b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RemusStealer_DGRS_2147972017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RemusStealer.DGRS!MTB"
        threat_id = "2147972017"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 0f b6 04 03 41 31 d0 41 31 d8 44 88 04 18 48 ff c3 48 39 d9 7e 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RemusStealer_PAA_2147972105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RemusStealer.PAA!MTB"
        threat_id = "2147972105"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {44 0f b6 04 03 41 31 d0 41 31 d8 44 88 04 18 48 ff c3 48 39 d9}  //weight: 3, accuracy: High
        $x_2_2 = {44 0f b6 04 03 49 89 d1 49 c1 f9 08 45 29 c8 44 88 04 18 48 ff c3 48 39 d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RemusStealer_MJ_2147972205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RemusStealer.MJ!MTB"
        threat_id = "2147972205"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 0c 30 80 f1 ?? 41 88 0c 00 41 ff c0 44 3b c7 72 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

