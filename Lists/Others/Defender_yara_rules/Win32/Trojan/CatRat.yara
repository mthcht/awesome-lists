rule Trojan_Win32_CatRat_A_2147755477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CatRat.A!MTB"
        threat_id = "2147755477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CatRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 0c 85 ?? ?? ?? ?? 8b 54 24 04 80 e9 ?? 88 0c 10 40 3d ?? ?? 00 00 7c e7 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 99 f7 7d dc 8b 45 88 0f be 0c 10 8b 55 d8 03 55 fc 0f be 02 33 c1 8b 4d d8 03 4d fc 88 01 eb c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CatRat_B_2147755491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CatRat.B!MTB"
        threat_id = "2147755491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CatRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 8b 14 8d ?? ?? 00 10 81 ea ?? 00 00 00 8b 45 08 03 45 fc 88 10 e9 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff ff 65 c6 45 ?? 6c c6 85 ?? ff ff ff 6e c6 45 ?? 32 c6 45 ?? 6f c6 45 ?? 75 c6 45 ?? 69 8d 85 ?? ff ff ff 50 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CatRat_C_2147755493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CatRat.C!MTB"
        threat_id = "2147755493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CatRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 b4 47 c6 45 b5 65 c6 45 b6 74 c6 45 b7 46 c6 45 b8 69 c6 45 b9 6c c6 45 ba 65 c6 45 bb 53 c6 45 bc 69 c6 45 bd 7a c6 45 be 65 c6 45 bf 00 8d 55 b4 52 8b 45 f8 50 ff 55 f4}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 c0 43 c6 45 c1 6c c6 45 c2 6f c6 45 c3 73 c6 45 c4 65 c6 45 c5 48 c6 45 c6 61 c6 45 c7 6e c6 45 c8 64 c6 45 c9 6c c6 45 ca 65 c6 45 cb 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 fc 99 f7 7d dc 8b 45 88 0f be 0c 10 8b 55 d8 03 55 fc 0f be 02 33 c1 8b 4d d8 03 4d fc 88 01 eb c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

