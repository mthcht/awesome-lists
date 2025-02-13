rule Trojan_Win64_SvcLoader_A_2147895786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SvcLoader.A!MTB"
        threat_id = "2147895786"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SvcLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 33 f6 33 d2 8d 4a 0a ff 15 ?? ?? 00 00 48 8b d8 48 85 c0 4c 8b 6d e8}  //weight: 2, accuracy: Low
        $x_2_2 = {c7 45 f0 30 01 00 00 33 d2 41 b8 2c 01 00 00 48 8d 4d f4 e8}  //weight: 2, accuracy: High
        $x_2_3 = {48 8d 55 f0 48 8b cb ff 15}  //weight: 2, accuracy: High
        $x_2_4 = {48 8d 4d 1c ff 15 ?? ?? 00 00 85 c0}  //weight: 2, accuracy: Low
        $x_2_5 = {48 8d 55 f0 48 8b cb ff 15 ?? ?? 00 00 85 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

