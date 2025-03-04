rule Trojan_Win64_DcRat_PAL_2147931478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DcRat.PAL!MTB"
        threat_id = "2147931478"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4b 45 52 4e 4c 8b e9 c7 85 ?? ?? ?? ?? 45 4c 33 32 8b cb c7 85 ?? ?? ?? ?? 2e 44 4c}  //weight: 2, accuracy: Low
        $x_1_2 = {80 30 11 48 8d 40 01 ff c1 83 f9 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

