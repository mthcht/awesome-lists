rule Trojan_Win64_PhotoZIP_GVA_2147972474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PhotoZIP.GVA!MTB"
        threat_id = "2147972474"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PhotoZIP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeShutdownPrivilege" wide //weight: 1
        $x_1_2 = "/CURRENTUSER" wide //weight: 1
        $x_1_3 = "/FORCENOCLOSEAPPLICATIONS" wide //weight: 1
        $x_1_4 = "File access denied" wide //weight: 1
        $x_1_5 = "Ya heek fo SA" wide //weight: 1
        $x_1_6 = "wmiapstic" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PhotoZIP_GVB_2147972475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PhotoZIP.GVB!MTB"
        threat_id = "2147972475"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PhotoZIP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f8 83 c4 04 89 7d e8 c6 45 fc 03 85 ff 74 34 ff 75 ec 0f 57 c0 56 51 0f 11 07 8b f4 c7 47 10 00 00 00 00 89 75 ec 8b 45 08 83 c0 f0 50 e8 49 c4 f6 ff 83 c4 04 83 c0 10 8b cf 89 06 e8 da eb ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "Proxifier.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PhotoZIP_GVC_2147972476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PhotoZIP.GVC!MTB"
        threat_id = "2147972476"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PhotoZIP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f b9 cd 6a 00 00 b3 c6 30 9c 0f 17 00 00 00 02 9c 0f 17 00 00 00 e2 f0}  //weight: 1, accuracy: High
        $x_1_2 = {58 b9 19 85 00 00 b3 0b 30 9c 08 17 00 00 00 02 9c 08 17 00 00 00 e2 f0}  //weight: 1, accuracy: High
        $x_1_3 = {5f b9 23 84 00 00 b2 1d 30 94 0f 17 00 00 00 02 94 0f 17 00 00 00 e2 f0}  //weight: 1, accuracy: High
        $x_1_4 = {5e b9 38 84 00 00 b3 a9 30 9c 0e 17 00 00 00 02 9c 0e 17 00 00 00 e2 f0}  //weight: 1, accuracy: High
        $x_1_5 = {5a b9 29 75 00 00 b3 09 30 9c 0a 17 00 00 00 02 9c 0a 17 00 00 00 e2 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_PhotoZIP_GVE_2147972477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PhotoZIP.GVE!MTB"
        threat_id = "2147972477"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PhotoZIP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 36 6a 00 ff 15 78 87 50 00 50 56 ff 15 70 87 50 00 0f b7 c0 8b d6 89 45 f8 66 3b c3 75 14}  //weight: 1, accuracy: High
        $x_1_2 = {8a 80 70 5b 51 00 30 45 ef 6a 04 5e 8a 41 fc 30 01 41 83 ee 01 75 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

