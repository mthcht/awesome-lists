rule Trojan_Win64_CovertRat_ACR_2147965826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CovertRat.ACR!MTB"
        threat_id = "2147965826"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CovertRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 06 b8 0a 00 00 00 48 89 46 08 48 8d 0d ?? 67 05 00 48 89 4e 10 b9 0b 00 00 00 48 89 4e 18 48 8d 15 ?? 67 05 00 48 89 56 20 ba 0c 00 00 00 48 89 56 28 4c 8d 05 ?? 67 05 00 4c 89 46 30 41 b8 0e 00 00 00 4c 89 46 38 4c 8d 0d}  //weight: 1, accuracy: Low
        $x_2_2 = {48 89 8e 98 00 00 00 48 8d 15 0b 67 05 00 48 89 96 a0 00 00 00 48 c7 86 a8 00 00 00 ?? ?? ?? ?? 48 8d 15 ff 66 05 00 48 89 96 b0 00 00 00 48 89 8e b8 00 00 00 48 8d 15 f5 66 05 00 48 89 96 c0 00 00 00 48 89 8e c8 00 00 00 48 8d 0d eb 66 05 00 48 89 8e d0 00 00 00 48 c7 86 d8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

