rule Trojan_Win64_BraZetsu_DA_2147977371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BraZetsu.DA!MTB"
        threat_id = "2147977371"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BraZetsu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {43 21 d3 23 43 26 f3 26 b3 28 33 2b e3 2c 63 30 d3 32 23 38 e3 39 a3 3b 33 40 d3 40 53 41 93 43 43 45 b3 46 33 48 d3 4b 93 5c d3 68 53 73 c3 7c 93 7d 13 7e b3 82 13 83 d3 83 53 84 c3 84 b3 88 23 8b d3 8c 93 a9 23 aa 33 ac a3 b0 a3 b1 83 b2 f3 b2 b3 b4 03 b6 63 b7 63 b9 d3 bc 93 be 43}  //weight: 10, accuracy: High
        $x_10_2 = {27 39 84 0b 6f 1b 23 7c 51 ff 85 84 e9 a2 18 95 8e 17 0c e9 7c 61 1f 74 6e 82 cb ea 93 9f 2a c2 84 aa 72 d0 4a 10 bf ec 94 bd 4a 10 7f 17 85 ac 97 f6 f4 82 65 b3 00 cf df 4a a6 fd 7b 88 74 59 a7 a1 58 c6 c3 f7 9a 70 02 fc e2 f0 8c ab d1 8f 08 81 d3 3f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

