rule Trojan_Win64_MintZard_A_2147923638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MintZard.A!MTB"
        threat_id = "2147923638"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MintZard"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 c7 48 c7 c1 9a 8e 00 00 f3 a4}  //weight: 1, accuracy: High
        $x_1_2 = {74 32 45 33 c0 48 83 7a 18 10 44 89 44 24 68 72 03 48 8b 12 4c 89 44 24 20 4c 8d 4c 24 68 44 8b c0}  //weight: 1, accuracy: High
        $x_1_3 = {55 48 89 e5 48 83 ec 08 44 8b d2 41 81 f0 6e 74 65 6c b9 17 00 00 00 48 83 c0 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

