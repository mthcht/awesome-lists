rule Trojan_Win32_Crinsis_A_2147709026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crinsis.A"
        threat_id = "2147709026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crinsis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e8 00 00 00 00 c7 85 ?? ?? ff ff 00 00 00 00 c7 85 ?? ?? ff ff 7a fc ff 7f 0f be 05 ?? ?? 00 10 0f be 0d ?? ?? 00 10}  //weight: 1, accuracy: Low
        $x_1_2 = {86 03 00 00 0f bf 0d ?? ?? 00 10 0f bf 15 ?? ?? 00 10 2b ca 89 [0-6] 0f be 05 ?? ?? 00 10 8b 0d ?? ?? 00 10 03 c8 89}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 e1 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab aa}  //weight: 1, accuracy: Low
        $x_1_4 = {99 f7 f9 0f bf 15 ?? 81 00 10 88 84 15 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {b9 06 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab c6 85 ?? ?? ff ff 00 b9 06 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab b9 4b 00 00 00 33 c0 8d bd ?? ?? ff ff f3 ab 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

