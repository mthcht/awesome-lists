rule Trojan_Win64_Sheheq_AT_2147919583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sheheq.AT!MTB"
        threat_id = "2147919583"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sheheq"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 66 33 44 74 20 66 89 44 74 20 66 31 44 54 20 48 ff c2 49 3b d1 72 c2 48 8b d3 4c 8b c3 fe c3 0f b6 db 02 54 5c 20 0f b6 d2 0f b7 44 54 20 66 31 44 5c 20 0f b7 44 5c 20 66 31 44 54 20 0f b7 44 54 20 66 33 44 5c 20 0f b7 c8 66 89 44 5c 20 0f b7 44 54 20 48 03 c1 0f}  //weight: 1, accuracy: High
        $x_1_2 = {c3 88 44 04 20 48 ff c0 48 3b c5 72 f4 4c 8b 0f 4c 8b c3 42 8a 54 04 20 41 8a c8 80 e1 07 49 8b c1 c0 e1 03 48 d3 e8 02 c2 40 02 c6 0f b6 f0 32 54 34 20 42 88 54 04 20 30 54 34 20 8a 44 34 20 42 30 44 04 20 49 ff c0 4c 3b c5 72 c6 4c 8b c3 48 8b d3 fe c3 0f b6 db 8a 4c 1c 20 41 8d 04 08 44 0f b6 c0 42 32 4c 04 20 88 4c 1c 20 42 30 4c 04 20 42 8a 44 04 20 32 44 1c 20 0f be c8 88 44 1c 20 42 0f be 44 04 20 03 c8 81 e1 ff 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

