rule Trojan_Win32_UrsnifCrypt_SK_2147756429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/UrsnifCrypt.SK!MTB"
        threat_id = "2147756429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "UrsnifCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 8b f0 b8 ?? ?? ?? ?? 2b c6 50 8b c6 e8 ?? ?? ?? ?? 85 c0 74 34 8b 4e 3c 8b 54 31 08 81 f2 ?? ?? ?? ?? 74 20 8b 48 0c 8b 74 24 08 8b 40 10 89 0e 8b 74 24 0c 89 06 03 c1 8b 4c 24 10 33 c2 89 01 33 c0 eb 0a 33 c0 40 eb 05}  //weight: 2, accuracy: Low
        $x_2_2 = {53 56 57 6a 09 8b f8 33 db 5e 8b 07 8b ce 83 e1 01 c1 e1 03 d3 e0 83 c7 04 03 d8 4e 85 f6 74 12 56 ff 74 24 14 ff 15 ?? ?? ?? ?? 3d 02 01 00 00 74 d8 5f 5e 8b c3 5b c2 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

