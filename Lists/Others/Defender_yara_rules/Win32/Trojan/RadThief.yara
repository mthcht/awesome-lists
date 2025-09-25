rule Trojan_Win32_RadThief_MXX_2147952618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RadThief.MXX!MTB"
        threat_id = "2147952618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RadThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {bb 9e 63 14 c4 0e 1a 33 c2 cb bb 12 51 cf 6e 3d bb e7 5c 2d 06 8a e0 03 38 96 cb 52 1b 46 4d b6 9b ?? bf 64 61 e4 9e f2 cf 28 75 de 1b 79 e9 8c a0 c3 bd e1 02 b8 db 64 ce b7 5d 53 80 31 72 59 7e e7 46 d7 c5 e1 26 da 4b 20 58 da 53 36}  //weight: 5, accuracy: Low
        $x_5_2 = {52 68 cf d9 a1 5d e9 91 02 1b 68 81 39 1c 36 7f be 70 0c b8 36 fc 6c 87 bd 52 db 6b ad b0 0b 93 26 ce 2b 93 d0 19 6b 80 a0 26 b6 c6 f3 2b b8 7d 00 b7 fb cf 3a 8b e7 79 05 0a cb eb 20 6a 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RadThief_MXZ_2147953081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RadThief.MXZ!MTB"
        threat_id = "2147953081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RadThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {42 fc d2 f8 b0 8d 67 4b 9d 27 96 3c 27 a6 ab 43 bb 9e 63 14 c4 0e 1a 33 c2 cb bb 12 51 cf 6e 3d bb e7 5c 2d 06 8a e0 03 38 96 cb 52 1b 46 4d b6 9b ?? bf 64 61 e4 9e f2 cf 28 75 d6 1b 79 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

