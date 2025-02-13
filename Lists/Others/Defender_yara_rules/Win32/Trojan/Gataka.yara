rule Trojan_Win32_Gataka_C_2147655569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gataka.C"
        threat_id = "2147655569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gataka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 20 6a 03 8d 4d ?? 51 8d 55 ?? 52 68 89 00 12 00 8d 45 ?? 50 ff 55}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e8 03 00 00 ff 15 ?? ?? ?? ?? e9 ?? ?? ff ff 68 10 27 00 00 ff 15 ?? ?? ?? ?? c6 45 fc 04}  //weight: 1, accuracy: Low
        $x_1_3 = {68 f8 00 00 00 8d 8d ?? ?? ff ff 51 8b 95 ?? ?? ff ff 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gataka_D_2147657027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gataka.D"
        threat_id = "2147657027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gataka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 03 50 8d 45 ?? c7 45 ?? 18 00 00 00 50 8d 45 fc 68 89 00 12 00 50 89 7d ?? c7 45 ?? 40 00 00 00 89 7d ?? 89 7d ?? ff 55 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {39 5d 08 74 04 3b c3 75 ?? 68 e8 03 00 00 ff 15 ?? ?? ?? ?? e9 ?? ?? ff ff 68 10 27 00 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

