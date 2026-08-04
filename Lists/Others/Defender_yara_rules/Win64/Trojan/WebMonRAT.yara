rule Trojan_Win64_WebMonRAT_DA_2147975177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WebMonRAT.DA!MTB"
        threat_id = "2147975177"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WebMonRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 0d c4 8d db da ac f9 da 6f 5d 80 b4 7c 62 47 70 e5 70 52 26 96 17 c2 a1 a2 cb 4e 3f 9d cd 77 1e 85 63 3b 48 55 b0 7e fa 0f d8 c4 62 fb d2 11 44 9c ac c2 1b 5d af ee f4 c0 19 99 17 b8 8f 87 48 ae 3d d2 de 45 73 be 54}  //weight: 1, accuracy: High
        $x_1_2 = {3b 46 1f 0f 10 a6 d9 0f 67 34 2e 02 a4 65 b9 df 69 98 a7 1b 75 e1 25 ba 81 83 4d 70 41 90 bd ac 8a f6 9a 65 98 6c 4b 9c 2a e9 53 eb d0 a3 92 67 6d 25 42 ca ed d7 7e c0 70 f9 28 2f 8d a7 10 39 b4 c8 b8 16 8c 97 b8 2e}  //weight: 1, accuracy: High
        $x_1_3 = {72 62 47 95 90 5c 6b 36 55 0c 75 33 60 4f a3 4d 53 d2 2b 2a 87 3b b8 04 49 ed f5 8a e9 ad 96 1d 56 f0 4c 58 b7 10 08 a8 8f ce 73 82 8a 65 a3 1c ea b2 d5 d6 0d 65 49 a4 02 5e fc ce a8 f9 ad 8f 76 a8 93 38 5a b4 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

