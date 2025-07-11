rule Trojan_Win32_Shellter_KK_2147946087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shellter.KK!MTB"
        threat_id = "2147946087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shellter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {0b f5 40 3b f2 79 ?? 48 c1 e6 04 2b fc 23 f5 ff c9 75}  //weight: 8, accuracy: Low
        $x_7_2 = {c1 e2 15 01 1d ?? ?? ?? ?? 2b f9 31 05 ?? ?? ?? ?? 33 d0 c1 c7 0a 8b fe c1 e0 13 2b 1d ?? ?? ?? ?? 81 ef 05 d7 e1 f4 01 05 ?? ?? ?? ?? 81 ca ad bb ec 35 bf c2 fc 9c df 81 f9 1a 29 9a 0b 7c ?? ?? ?? ?? ?? ?? ?? ?? c1 cb 10 33 d1 ff c9 75}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

