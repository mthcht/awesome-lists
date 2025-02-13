rule Trojan_Win64_LazyInjector_ZZ_2147927465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LazyInjector.ZZ!MTB"
        threat_id = "2147927465"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LazyInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 68 44 8b 40 50 48 8b 44 24 68 48 8b 50 30 48 8b 44 24 60 48 8b 08}  //weight: 1, accuracy: High
        $x_1_2 = {48 01 c8 48 05 08 01 00 00 48 6b 4c 24 78 28 48 01 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_LazyInjector_ZY_2147927466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LazyInjector.ZY!MTB"
        threat_id = "2147927466"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LazyInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 39 95 60 05 00 00 76 28 48 8d 8d 20 01 00 00 66 90 0f b6 01 ff c2 ff c3 42 88 04 27 8b 85 60 05 00 00 48 ff c7 48 ff c1 3b d0 72 e5 85 c0 75 b1 48 8b ce ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

