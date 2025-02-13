rule Trojan_Win64_ShellCoExec_A_2147918814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCoExec.A!MTB"
        threat_id = "2147918814"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCoExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 63 c1 48 b8 5f 43 79 0d e5 35 94 d7 41 ff c1 49 f7 e0 48 c1 ea 04 48 6b c2 13 4c 2b c0 41 8b c3 44 03 db 99 4d 03 c7 f7 fb 48 63 c8 48 b8 d0 93 1c 40 01 00 00 00 48 03 c1 42 8a 4c 04 20 32 0c 30 41 88 0a 49 ff c2 41 81 f9 00 12 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ShellCoExec_B_2147918815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCoExec.B!MTB"
        threat_id = "2147918815"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCoExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b7 cb 48 63 ed 66 99 48 13 fd 41 0f b6 eb 4c 8b 54 43 e2 d3 c2 0f ba e0 b9 48 8b 44 13 08 66 c1 fa e7 8a 4c 13 10 2b ea 48 8d 5c 53 0a 66 c1 ed 2a c0 fa 87 49 0f a5 c2 4c 89 14 13 48 03 d7 ff e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

