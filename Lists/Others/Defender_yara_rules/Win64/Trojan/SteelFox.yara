rule Trojan_Win64_SteelFox_AFO_2147925988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SteelFox.AFO!MTB"
        threat_id = "2147925988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SteelFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 c1 e9 10 0f b6 f8 32 d1 41 c0 f8 07 41 80 e0 1b 40 c0 ff 07 40 80 e7 1b 8b c8 c1 e9 08 8b f0 32 d1 c1 ee 18 41 32 d0 8b d8 40 32 d7 c1 eb 10 88 54 24 70 44 32 db 40 0f b6 d6 45 02 db 40 32 f0 32 d3 02 d2 40 02 f6 44 8b c8 44 8b d0 41 c1 e9 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

