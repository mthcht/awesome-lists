rule Trojan_Win64_InjectorCrypt_SO_2147762008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/InjectorCrypt.SO!MTB"
        threat_id = "2147762008"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "InjectorCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 01 c3 48 35 00 8b 05 ?? ?? 00 00 35 ?? ?? ?? ?? 89 41 04 8b 05 ?? ?? 00 00 35}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 54 41 55 41 56 48 81 ec d0 00 00 00 4c 8b 15 ?? ?? ?? ?? 49 8b e9 4d 8b e0 4d 8b 9a ?? ?? ?? ?? 44 8b ea 4c 8b f1 4d 85 db 0f 84 ?? ?? ?? ?? 48 8d 4c 24 50 e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? e8 ?? ?? ?? ?? 41 8b 92}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

