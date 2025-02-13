rule Trojan_Win64_PackZ_AMS_2147851791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PackZ.AMS!MTB"
        threat_id = "2147851791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d1 01 ce 8b 13 bf ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 81 e2 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 01 f7 81 ef ?? ?? ?? ?? 31 10 09 f9 49 40 bf ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 43 21 fe 89 f1 09 f9 81 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

