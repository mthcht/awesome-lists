rule Trojan_Win64_Ravartar_PGRT_2147968505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ravartar.PGRT!MTB"
        threat_id = "2147968505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ravartar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 00 63 6d 64 2e 65 78 65 00 78 6d 72 69 67 2e 65 78 65 00 6d 69 6e 65 72 2e 65 78 65 ?? ?? ?? ?? ?? ?? 63 6d 64 2e 65 78 65 20 2f 63 20 70 69 6e 67 20 2d 6e 20 35 20 31 32 37 2e 30 2e 30 2e 31 20 3e 6e 75 6c 20 32 3e 26 31 20 26 26 20 64 65 6c 20 2f 66 20 2f 71 20 22 25 73 22}  //weight: 5, accuracy: Low
        $x_5_2 = {d1 51 a6 50 82 51 a6 50 82 51 a6 50 82 25 27 51 83 53 a6 50 82 58 de c3 82 5a a6 50 82 51 a6 51 82 72 a6 50 82 51 a6 50 82 50 a6 50 82 1a 2c 54 83 41 a6 50 82 1a 2c 55 83 4e a6 50 82 1a 2c 53 83 44 a6 50 82 1a 2c 50 83 50 a6 50 82 1a 2c af 82 50 a6 50 82 1a 2c 52 83 50 a6 50}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ravartar_ARR_2147974077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ravartar.ARR!MTB"
        threat_id = "2147974077"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ravartar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {03 d0 0f b7 c2 6b d0 ?? 0f b7 c1 ff c1 66 2b c2 66 83 c0 3a 66 41 31 40 fe 83 f9 29}  //weight: 11, accuracy: Low
        $x_5_2 = {66 0f fe c1 66 0f 38 40 c6 66 0f fa d0 f3 0f 70 c2 ?? f3 0f 7e d7 f2 0f 70 c8 ?? f3 0f 7e 42 f8 66 0f 70 d9 ?? 66 0f fd da 0f 57 d8 66 0f d6 5a f8}  //weight: 5, accuracy: Low
        $x_4_3 = "[DEBUG] Viewport Hooked" ascii //weight: 4
        $x_3_4 = "[DEBUG] Getting ViewportClient..." ascii //weight: 3
        $x_2_5 = "[DEBUG] LocalController: %p" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

