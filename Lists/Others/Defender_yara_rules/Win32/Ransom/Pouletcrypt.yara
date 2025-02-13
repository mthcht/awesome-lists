rule Ransom_Win32_Pouletcrypt_A_2147711671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pouletcrypt.A"
        threat_id = "2147711671"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pouletcrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 00 00 00 00 ff ff ff ff ?? 00 00 00 [0-16] 00 00 ff ff ff ff ?? 00 00 00 52 61 7a 64 31 [0-8] 00 00 ff ff ff ff}  //weight: 1, accuracy: Low
        $x_2_2 = {b9 01 00 00 00 e8 ?? ?? ?? ff ff 0d ?? ?? ?? 00 8b ?? 8b 15 ?? ?? ?? 00 80 7c 10 ff 21 74 d6 [0-48] 85 c0 7e 17 ba 01 00 00 00 8b 0d ?? ?? ?? 00 80 7c 11 ff 2f 75 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

