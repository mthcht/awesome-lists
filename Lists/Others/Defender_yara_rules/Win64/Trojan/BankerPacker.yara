rule Trojan_Win64_BankerPacker_IA_2147896526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BankerPacker.IA!MTB"
        threat_id = "2147896526"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BankerPacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 c0 b8 ?? ?? ?? ?? f7 ef c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 8b cf 2b c8 48 63 c1 41 8a 0c 18 42 32 8c 30 ?? ?? ?? ?? 48 8b 44 24 40 88 0c 06 ff c7 48 ff c6 48 63 c7 48 3b 44 24 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

