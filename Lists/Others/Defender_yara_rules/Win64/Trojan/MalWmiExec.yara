rule Trojan_Win64_MalWmiExec_A_2147932431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MalWmiExec.A!MTB"
        threat_id = "2147932431"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MalWmiExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b e0 89 5c 24 70 48 8d 7d e0 41 bd 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4a 8b 4c e1 28 4c 8d 4c 24 30 41 b8 00 10 00 00 48 89 7c 24 20 48 8d 54 24 40}  //weight: 1, accuracy: High
        $x_1_3 = {8b 54 24 30 33 c9 ff 15 ?? ?? ?? ?? 48 8b f8 48 85 c0 0f 84 ?? ?? ?? ?? 48 8d 44 24 30 48 89 44 24 20 44 8b 4c 24 30 4c 8b c7 ba 19 00 00 00 48 8b 4c 24 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_MalWmiExec_B_2147932432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MalWmiExec.B!MTB"
        threat_id = "2147932432"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MalWmiExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 10 4c 24 40 0f 11 4d 98 0f 10 45 b8 0f 11 45 a8 48 8d 55 98 66 48 0f 7e c8 48 83 fb 0f 48 0f 47 d0 33 db 48 89 5c 24 20 4c 8d 4c 24 70 66 41 0f 7e c0 49 8b cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

