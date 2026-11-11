rule Trojan_Win64_Valley_MK_2147979421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Valley.MK!MTB"
        threat_id = "2147979421"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {48 89 44 24 40 89 6c 24 38 4c 89 7c 24 28 48 89 6c 24 58 89 7c 24 50 66 c7 44 24 20 04 01 48 8b 03 41 b8 02 00 00 00 48 8d 54 24 20 48 8b cb ff 50 18 48 8b 03}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Valley_MK_2147979421_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Valley.MK!MTB"
        threat_id = "2147979421"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b 4d a7 48 8b 7d 9f 48 2b cf 48 b8 a3 8b 2e ba e8 a2 8b 2e 48 f7 e9 4c 8b fa 49 c1 ff 05 49 8b c7 48 c1 e8 3f 4c 03 f8}  //weight: 20, accuracy: High
        $x_15_2 = "ClipboardWinBackend" wide //weight: 15
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Valley_MK_2147979421_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Valley.MK!MTB"
        threat_id = "2147979421"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {41 0f b6 0c 2e 4d 8d 5b 01 4c 8b 03 b8 dd 47 70 1f f7 e1 8b c1 45 8b ca 2b c2 d1 e8 03 c2 c1 e8 08 69 c0 c8 01 00 00 2b c8 b8 cd cc cc cc 41 f7 e2 80 c1 36 48 8d 45 01 43 30 4c 03 ff 33 ed c1 ea 03 41 ff c2 8d 0c 92 03 c9 44 3b c9 48 0f 45 e8 44 3b d6}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Valley_AB_2147979514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Valley.AB!MTB"
        threat_id = "2147979514"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = {41 0f b6 d5 c1 e2 ?? 09 c2 41 0f b6 c2 c1 e0 ?? 09 d0 41 0f b6 d4 c1 e2 ?? 09 c2 66 0f 6e e2 0f b6 44 24 70}  //weight: 12, accuracy: Low
        $x_8_2 = {66 0f 6e e9 66 44 0f 6f c5 66 44 0f fc c5 66 0f ef c0 66 0f 64 c5 66 0f 6f d0 66 41 0f df d0 66 44 0f ef c1 66 44 0f db c0 66 44 0f eb c2 66 45 0f ef e4}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Valley_MKA_2147979811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Valley.MKA!MTB"
        threat_id = "2147979811"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_35_1 = {44 8d 41 ff 4d 63 c0 34 ?? 41 88 04 10 48 63 c9 0f b6 04 11 ff c1 84 c0}  //weight: 35, accuracy: Low
        $x_35_2 = {41 88 00 48 63 d2 4c 8d 04 11 0f b6 04 0a ff c2 84 c0}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Valley_KK_2147981862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Valley.KK!MTB"
        threat_id = "2147981862"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {41 0f b6 3c 72 8d 5f bf 8d 6f 20 80 fb 1a 40 0f b6 dd 0f 43 df 41 6b fb 21 44 0f b6 db 41 31 fb 48 ff c6}  //weight: 20, accuracy: High
        $x_10_2 = {44 8b 4c 08 18 44 8b 44 08 1c 44 8b 5c 08 20 44 8b 54 08 24 49 01 cb 31 c0 31 ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

