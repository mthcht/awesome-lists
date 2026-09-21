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

