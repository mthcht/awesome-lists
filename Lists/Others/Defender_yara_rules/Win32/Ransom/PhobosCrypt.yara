rule Ransom_Win32_PhobosCrypt_SK_2147756277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PhobosCrypt.SK!MTB"
        threat_id = "2147756277"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PhobosCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 29 2c e4 89 04 e4 ff 93 ?? ?? ?? ?? 52 33 14 e4 09 c2 83 e7 00 31 d7 5a 89 4d f8 31 c9 31 f9 89 8b ?? ?? ?? ?? 8b 4d f8 83 fb 00 76}  //weight: 2, accuracy: Low
        $x_2_2 = {f3 a4 56 c7 04 e4 ff ff 0f 00 59 89 7d f8 29 ff 0b bb ?? ?? ?? ?? 89 f8 8b 7d f8 55 81 04 e4 ?? ?? ?? ?? 29 2c e4 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 89 4d f8 8b 8b ?? ?? ?? ?? 01 c1 51 8b 4d f8 58 ff e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

