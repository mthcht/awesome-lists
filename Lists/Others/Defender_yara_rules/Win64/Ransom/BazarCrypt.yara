rule Ransom_Win64_BazarCrypt_SV_2147770174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BazarCrypt.SV!MTB"
        threat_id = "2147770174"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 33 c9 45 8b c4 33 d2 48 8b ?? ?? ?? 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ff ff ff d3 b9 00 0c 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {ba 61 1e 00 00 41 b8 14 00 00 00 4c 8d 25 ?? ?? ?? ?? 49 8b cc ff d3 48 8b d8 48 8b d0 49 8b cc ff d7 48 8b f8 48 8b d3 49 8b cc ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = {ba 01 68 00 00 48 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ff ff 48 8d 0d 97 d7 01 00 e8 ?? ?? 00 00 44 8b c8 8b 54 ?? ?? 33 c9 41 b8 00 10 00 00 ff 15 ?? ?? ?? ?? 48 8b d8 44 8b ?? ?? ?? 48 8b d7 48 8b c8 e8 ca 25 00 00 44 8b ?? ?? ?? 44 89}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_BazarCrypt_SX_2147772846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BazarCrypt.SX!MTB"
        threat_id = "2147772846"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 49 89 c8 48 81 c1 ?? ?? 00 00 ba ?? ?? ?? ?? 49 81 c0 ?? ?? ?? ?? 41 b9 05 00 00 00 56 48 89 e6 48 83 e4 f0 48 83 ec 30 c7 44 24 ?? 01 00 00 00 e8 ?? 00 00 00 48 89 f4 5e c3}  //weight: 2, accuracy: Low
        $x_2_2 = {b9 4c 77 26 07 44 8b fa 33 db e8 ?? ?? 00 00 b9 49 f7 02 78 4c 8b e8 e8 ?? ?? 00 00 b9 58 a4 53 e5 48 89 44 24 ?? e8 ?? ?? 00 00 b9 10 e1 8a c3 48 8b f0 e8 ?? ?? 00 00 b9 af b1 5c 94}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

