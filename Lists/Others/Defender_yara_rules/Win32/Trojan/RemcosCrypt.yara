rule Trojan_Win32_RemcosCrypt_GG_2147773251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemcosCrypt.GG!MTB"
        threat_id = "2147773251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemcosCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 99 8b 55 ?? 8b 4d ?? 33 04 8a 8b 55 ?? 8b 4d ?? 89 04 8a 66 a1 [0-4] 66 3b 05 3c 00 8b 15 [0-4] 33 15 [0-4] 3b 15 [0-4] 8b 4d ?? 8b 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

