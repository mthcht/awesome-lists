rule Trojan_Win64_Oyster_AA_2147908622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.AA!MTB"
        threat_id = "2147908622"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d0 8b 85 ?? ?? ?? ?? 48 89 54 c5 ?? 83 85 ?? ?? ?? ?? 01 81 bd ?? ?? ?? ?? ?? ?? 00 00 76 ?? 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {48 63 d0 8b 85 ?? ?? ?? ?? 48 89 54 c5 ?? 83 85 ?? ?? ?? ?? 01 81 bd ?? ?? ?? ?? ?? ?? 00 00 0f 86 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Oyster_A_2147913092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.A"
        threat_id = "2147913092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 58 45 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 54 65 73 74 00 43 4f 4d 00 6f 70 65 6e 00 74 65 6d 70 00 25 73 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Oyster_YAD_2147953809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.YAD!MTB"
        threat_id = "2147953809"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "@USVWATAUAVAW" ascii //weight: 20
        $x_1_2 = {48 b8 24 07 c0 e9 03 48 c7 c3}  //weight: 1, accuracy: High
        $x_1_3 = {48 b8 72 17 de a6 5c 28 c7 56}  //weight: 1, accuracy: High
        $x_1_4 = {48 b8 6f 15 4a 89 86 dc 95 a1}  //weight: 1, accuracy: High
        $x_1_5 = {48 b8 a7 e0 9c fe 3f f0 5c cd}  //weight: 1, accuracy: High
        $x_1_6 = {48 b8 35 5b 03 93 e9 1f ad fe}  //weight: 1, accuracy: High
        $x_1_7 = {48 b8 4d 58 c1 08 47 6e 01 e1}  //weight: 1, accuracy: High
        $x_1_8 = {48 b8 08 91 12 09 60 74 52 ac}  //weight: 1, accuracy: High
        $x_1_9 = {48 b8 2d 13 71 8e 9d 75 9c 30}  //weight: 1, accuracy: High
        $x_1_10 = {48 b8 37 4a 89 16 31 10 10 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

