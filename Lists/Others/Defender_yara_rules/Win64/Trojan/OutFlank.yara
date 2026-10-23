rule Trojan_Win64_OutFlank_DA_2147969056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OutFlank.DA!MTB"
        threat_id = "2147969056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OutFlank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 20 35 d1 0a 00 00 34 11 48 8b 54 24 28 38 03 75 1f 44 89 5c 24 20 c7 44 24 20 16 4c 63 31 8b 44 24 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OutFlank_DB_2147978433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OutFlank.DB!MTB"
        threat_id = "2147978433"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OutFlank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 47 08 49 2b c1 48 c1 f8 02 4c 8b 13 4c 89 54 24 58 48 8b 4b 08 49 2b ca 48 c1 f9 02 45 8b eb 8b c0 48 89 44 24 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OutFlank_MZF_2147980846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OutFlank.MZF!MTB"
        threat_id = "2147980846"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OutFlank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6f 77 65 72 43 68 65 6c 6c 2e 64 6c 6c 00 53 74 61 72 74 00 00 c0 3a 02 00 00 00 00 00 00 00 00 00 6a 3e 02 00 00 80 01}  //weight: 1, accuracy: High
        $x_1_2 = {30 80 00 00 80 13 00 00 3b 80 00 00 00 00 74 65 73 74 2e 64 6c 6c 00 45 6e 74 72 79 50 6f 69 6e 74}  //weight: 1, accuracy: High
        $x_1_3 = {70 79 74 68 6f 6e 33 39 2e 64 6c 6c 00 43 61 6c 63 43 69 72 63 75 6d 00 43 61 6c 6c 65 72 45 78 61 6d 70 6c 65 00 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

