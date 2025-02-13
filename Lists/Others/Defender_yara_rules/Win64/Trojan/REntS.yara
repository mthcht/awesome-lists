rule Trojan_Win64_REntS_SIB_2147780524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/REntS.SIB!MTB"
        threat_id = "2147780524"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {44 8b 5c 24 ?? 8b 44 24 ?? 41 8d 84 03 00 01 00 00 [0-8] 89 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 83 c0 04 89 44 24 ?? 8b 05 ?? ?? ?? ?? 39 44 24 ?? 72 ?? 33 c0}  //weight: 20, accuracy: Low
        $x_20_2 = {4c 8b d8 8b 05 ?? ?? ?? ?? 41 03 c3 8b c8 48 8b 05 ?? ?? ?? ?? 0f b6 0c 08 48 8b 05 ?? ?? ?? ?? 0f b6 14 18 03 d1 8b 0d ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 88 14 08}  //weight: 20, accuracy: Low
        $x_1_3 = "{aa5b6a80-b834-11d0-932f-00a0c90dcaa9}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_REntS_SIBB_2147796756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/REntS.SIBB!MTB"
        threat_id = "2147796756"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c0 48 63 d0 4c 63 c0 4e 0f b6 04 01 41 80 f0 ?? 44 88 84 14 ?? ?? ?? ?? 83 c0 01 83 f8 ?? 75 ?? 90 c6 84 24 ?? ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 48 33 c0 48 63 d0 4c 63 c0 4e 0f b6 04 01 41 80 f0 ?? 44 88 84 14 ?? ?? ?? ?? 83 c0 01 83 f8 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {48 bb 60 00 00 00 00 00 00 00 65 48 8b 03 48 8b 40 18 48 8b 40 ?? 48 8b 00 48 8b 00 48 8b 40 10}  //weight: 1, accuracy: Low
        $x_1_3 = {48 63 40 3c 48 8d 04 03 8b 80 88 00 00 00 4c 8d 34 18 4d 33 ed 48 33 ff 41 8b 46 20 48 8d 04 18 41 8b cd 03 c9 03 c9 [0-5] 8b 04 08 48 8d 04 18 48 89 c1 48 89 f2 e8 ?? ?? ?? ?? 84 c0 74 ?? 41 8b c5 03 c0 41 03 46 24 8b c0 48 0f b7 04 18 66 83 e0 ff 0f b7 c0 03 c0 03 c0 41 03 46 1c 8b c0 8b 04 18 48 8d 3c 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_REntS_SIBC_2147807250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/REntS.SIBC!MTB"
        threat_id = "2147807250"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "REntS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "Leaked Heap Address" ascii //weight: 10
        $x_1_2 = {44 8b da 48 85 c0 75 ?? b8 ?? ?? ?? ?? eb ?? 4c 8b d0 48 8b 81 ?? ?? ?? ?? 48 d1 e8 4d 8d 42 ?? 4c 03 c0 4c 89 41 ?? 8b 41 ?? 85 c0 7f ?? 45 85 db 74 ?? ff c8 33 d2 89 41 ?? 41 8b c3 f7 f3 80 c2 ?? 44 8b d8 80 fa ?? 7e ?? 41 8a c1 34 ?? c0 e0 ?? 04 ?? 02 d0 48 8b 41 ?? 88 10 48 ff 49 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

