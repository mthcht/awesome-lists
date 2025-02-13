rule Trojan_Win64_AresLdr_MA_2147846512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AresLdr.MA!MTB"
        threat_id = "2147846512"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AresLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 03 c1 41 8b c8 03 d1 8b ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 44 8b 05 ?? ?? ?? ?? 44 03 c1 41 8b c8 03 d1 8b ca 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b ca 03 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 48 63 c9 48 8b 94 24 70 03 00 00 88 04 0a e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

