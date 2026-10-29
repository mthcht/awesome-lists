rule Trojan_Win64_GoCrypt_C_2147976519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCrypt.C!MTB"
        threat_id = "2147976519"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 34 03 31 ce 4c 8d 04 9b 41 31 f0 44 88 04 18 48 ff c3 [0-1] 48 39 da 7f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoCrypt_CH_2147978111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCrypt.CH!MTB"
        threat_id = "2147978111"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 34 03 31 ce 48 8d 3c 9b 31 fe 40 88 34 18 48 ff c3 48 39 da 7f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoCrypt_CH_2147978111_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCrypt.CH!MTB"
        threat_id = "2147978111"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 29 c2 48 6b d2 ?? 4d 89 d8 49 29 d3 45 31 d3 48 89 ca 48 c1 e1 ?? 48 29 d1 44 31 d9 88 0c 13}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoCrypt_CK_2147978537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCrypt.CK!MTB"
        threat_id = "2147978537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 0f b6 14 10 45 31 c2 4c 8d 1c 80 45 31 da 44 88 14 02 48 ff c0 49 39 c1 7f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoCrypt_CQ_2147979832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCrypt.CQ!MTB"
        threat_id = "2147979832"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {47 0f b6 5c 0b 02 41 83 c3 d0 45 0f b6 db 4d 01 e3 46 0f b6 24 00 45 31 e3 44 88 1c 02 48 ff c0 4c 39 d0}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoCrypt_CM_2147980184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCrypt.CM!MTB"
        threat_id = "2147980184"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 0f b6 d2 4d 01 da 44 0f b6 1c 3b 45 31 da 44 88 14 1e 48 ff c3 48 81 fb ?? ?? ?? ?? 7d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoCrypt_CN_2147980234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCrypt.CN!MTB"
        threat_id = "2147980234"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 31 c2 49 89 d8 48 c1 e3 ?? 4c 29 c3 44 31 d3 42 88 1c 06 4c 89 c3 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoCrypt_CO_2147980908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCrypt.CO!MTB"
        threat_id = "2147980908"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 14 01 48 8d 1c 49 48 8d 1c 59 29 da 83 c2 ?? 88 14 08 48 ff c1 48 81 f9 ?? ?? ?? ?? 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_GoCrypt_CP_2147981154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoCrypt.CP!MTB"
        threat_id = "2147981154"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {44 0f b6 1c 10 45 31 c3 4c 8d 24 80 45 31 e3 44 88 1c 02 48 ff c0 49 39 c1 7f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

