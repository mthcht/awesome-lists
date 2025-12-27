rule Trojan_Win64_CoinStealer_SX_2147948338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinStealer.SX!MTB"
        threat_id = "2147948338"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 8b 0e 4c 8d 45 60 48 8d 95 c0 00 00 00 ff 15 ?? ?? ?? ?? 0f 57 c0 0f 11 85 c0 00 00 00 48 8b df 48 89 9d d0 00 00 00 41 bc 0f 00 00 00}  //weight: 5, accuracy: Low
        $x_3_2 = {48 8b d8 48 8d 8d 28 02 00 00 48 83 bd 40 02 00 00 0f 48 0f 47 8d 28 02 00 00 48 ff c7 44 38 24 39 75 f7 48 8d 95 28 02 00 00 48 83 bd 40 02 00 00 0f 48 0f 47 95 28 02 00 00 4c 89 64 24 20 4c 8d 8d a8 01 00 00 44 8b c7 48 8b cb}  //weight: 3, accuracy: High
        $x_2_3 = {f3 0f 6f 8c 08 ?? ?? ?? ?? f3 0f 6f 84 05 a0 00 00 00 0f 57 c8 f3 0f 7f 8c 05 a0 00 00 00 48 83 c0 10 48 83 f8 70 7c d8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

