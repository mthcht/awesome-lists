rule Trojan_Win64_DllInjector_BAA_2147969008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DllInjector.BAA!MTB"
        threat_id = "2147969008"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DllInjector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 fa 03 77 18 8b c2 48 8d 15 fa 57 06 00 8b 14 82 4c 8d 15 e8 ff ff ff 49 03 d2 ff e2 b8 04 00 00 00 c3 48 8d 05 36 87 04 00 49 89 00 38 09 33 c0 eb 37 48 8d 05 7e 98 04 00 49 89 00 38 09 b8 10 00 00 00 eb 24 48 8d 05 ab c3 04 00 49 89 00 38 09 b8 18 00 00 00 eb 11 48 8d 05 f0 9a 04 00 49 89 00 38 09 b8 08 00 00 00 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

