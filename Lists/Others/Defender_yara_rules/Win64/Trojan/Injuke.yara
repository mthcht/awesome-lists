rule Trojan_Win64_Injuke_CRUV_2147848209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.CRUV!MTB"
        threat_id = "2147848209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 18 8b 44 24 08 99 83 e0 ?? 33 c2 2b c2 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injuke_CRUW_2147848211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.CRUW!MTB"
        threat_id = "2147848211"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 74 99 83 e0 ?? 33 c2 2b c2 85 c0 74 ?? 8b 44 24 74 ff c0 89 44 24 74 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injuke_NI_2147924817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.NI!MTB"
        threat_id = "2147924817"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {45 0f b7 df 44 0f af da 4d 63 db 49 63 fd 4d 01 cb 42 80 3c 1f 05}  //weight: 3, accuracy: High
        $x_2_2 = {45 0f b7 df 44 0f af da 4d 63 db 42 80 7c 1e 06 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Injuke_GVA_2147940271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Injuke.GVA!MTB"
        threat_id = "2147940271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 89 c2 46 8a 1c 00 89 c1 80 e1 03 41 d2 cb 41 83 e2 0f 43 8a 0c 0a 80 e1 0f 44 30 d9 88 0c 32 48 ff c6 48 ff c0 48 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

