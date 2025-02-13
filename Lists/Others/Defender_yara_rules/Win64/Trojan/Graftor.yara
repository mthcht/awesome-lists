rule Trojan_Win64_Graftor_B_2147915189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Graftor.B!MTB"
        threat_id = "2147915189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 23 d1 80 da ?? 44 33 c7 41 f7 d8 c0 e2 ?? 48 81 f2 ?? ?? ?? ?? 41 81 f0 ?? ?? ?? ?? 41 0f c8}  //weight: 2, accuracy: Low
        $x_4_2 = {d2 f8 66 45 0b f1 41 57 44 0f c0 d5 66 45 33 d0 48 83 ec ?? 4d 0f a3 f8 4c 8b 79 ?? 48 8b c1 49 0f ab e2 8b 49 ?? c1 df a4 41 c0 f2 bd 2b ?? 41 b2 ?? 66 41 0f c8 4c 8b c2 41 c0 c6}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Graftor_C_2147916119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Graftor.C!MTB"
        threat_id = "2147916119"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 d1 ff c1 41 51 42 31 8c 1c ?? ?? ?? ?? 44 23 d2 41 59 40 0a d7 40 0a f7 48 03 c6 48 63 c9 40 c0 cf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Graftor_D_2147916541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Graftor.D!MTB"
        threat_id = "2147916541"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 2a db d3 e2 41 81 f6 ?? ?? ?? ?? 4c 2b d3 8b 48 ?? 41 0f ab c6 45 12 f0 41 d3 de 4c 8b f3 d3 e7 49 0f 45 eb 48 ff cd 66 41 ff c2 48 8b 8c 24 ?? ?? ?? ?? ff ca 41 0f 99 c2 ff cf 66 41 0f a3 ca 66 41 0f ac f2 ?? 40 0f ?? ?? 8b eb 41 b2 ?? 45 0f c0 d2 45 8b d4 89 7c 24 ?? 40 d2 d7 8b 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Graftor_E_2147919932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Graftor.E!MTB"
        threat_id = "2147919932"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 19 48 c1 c9 ?? 8b 40 ?? 66 0b cc 66 41 0f 45 c9 66 f7 d1 89 54 24 ?? f8 87 c9 8d 0c 07 b8 ?? ?? ?? ?? 41 3a f1 f8 89 7c 24 ?? 66 81 fc ?? ?? d3 e0 f5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

