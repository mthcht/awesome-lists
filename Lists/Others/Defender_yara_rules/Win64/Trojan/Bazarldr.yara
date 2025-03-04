rule Trojan_Win64_BazarLdr_2147777659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLdr!MTB"
        threat_id = "2147777659"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 40 0f ba e8 0c 44 8b c0 44 8b cb 33 c9 ff 15 [0-32] 4c 8d 4c ?? ?? 4c 8b c3 ba 01 00 00 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 4d 20 48 8d 45 f0 48 83 65 f0 00 48 8d 15 ?? ?? ?? ?? 48 89 44 24 28 45 33 c9 83 64 24 20 00 41 b8 ?? ?? ?? ?? ff 15 [0-48] 4c 8d 05 ?? ?? ?? ?? 49 ff c8 4c 03 c3 33 d2 41 8a 00 49 ff c8 42 88 44 22 0c 48 ff c2 48 3b d3 7c ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

