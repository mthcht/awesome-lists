rule Trojan_Win64_GoGRPC_GVA_2147974719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoGRPC.GVA!MTB"
        threat_id = "2147974719"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoGRPC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8d 0c 9b 45 0f b6 c0 48 ff c1 4b 8d 1c 48 48 39 d1 7d 1c 44 0f b6 04 0e 41 83 c0 d0 0f 1f 40 00 41 80 f8 09 76 d9 31 c9 31 d2 e9 fb f7 ff ff b9 01 00 00 00 48 89 da e9 ee f7 ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "call frame too large" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoGRPC_GVB_2147974720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoGRPC.GVB!MTB"
        threat_id = "2147974720"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoGRPC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8d 64 24 b0 4d 3b 66 10 0f 86 ff 02 00 00 55 48 89 e5 48 81 ec c8 00 00 00 48 8b 1d 9f ?? 61 00 48 8b 0d a0 ?? 61 00 48 8b 05 31 ?? 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 8d 64 24 b0 4d 3b 66 10 0f 86 ff 02 00 00 55 48 89 e5 48 81 ec c8 00 00 00 48 8b 1d 3f 31 61 00 48 8b 0d 40 31 61 00 48 8b 05 d1 78 63 00 e8 4c b2 cd ff}  //weight: 1, accuracy: High
        $x_1_3 = {4c 8d a4 24 60 ff ff ff 4d 3b 66 10 0f 86 41 05 00 00 55 48 89 e5 48 81 ec 18 01 00 00 66 44 0f d6 bc 24 10 01 00 00 c6 44 24 3f 00 48 8b 0d e5 95 5c 00 48 8b 15 d6 95 5c 00 48 85 c9 74 09}  //weight: 1, accuracy: High
        $x_1_4 = {4c 8d 64 24 b0 4d 3b 66 10 0f 86 ff 02 00 00 55 48 89 e5 48 81 ec c8 00 00 00 48 8b 1d ff 3e 61 00 48 8b 0d 00 3f 61 00 48 8b 05 91 86 63 00 e8 ac b1 cd ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_GoGRPC_GVC_2147974721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoGRPC.GVC!MTB"
        threat_id = "2147974721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoGRPC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a0 a5 b0 a5 c0 a5 d8 a5 e0 a5 e8 a5 f0 a5 f8 a5 00 a6 18 a6 30 a6 38 a6 40 a6 b8 ac e8 ac b0 ad c8 ad e0 ad e8 ad 00 ae 08 ae 10 ae 18 ae 20 ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoGRPC_GVD_2147974722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoGRPC.GVD!MTB"
        threat_id = "2147974722"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoGRPC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.Request" ascii //weight: 1
        $x_1_2 = "main.oscillate" ascii //weight: 1
        $x_1_3 = "main.dominate" ascii //weight: 1
        $x_1_4 = "main.synthesize" ascii //weight: 1
        $x_1_5 = "main.decline" ascii //weight: 1
        $x_1_6 = "main.metamorphose" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

