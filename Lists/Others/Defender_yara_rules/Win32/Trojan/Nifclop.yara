rule Trojan_Win32_Nifclop_A_2147654644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nifclop.A"
        threat_id = "2147654644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nifclop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 2d 07 00 8d 4d 98 0f 80 ?? ?? 00 00 0f bf c0 50 51}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 79 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? 8d 95 ?? ?? ff ff 6a 70 52 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 6a 6e 50 ff 15 ?? ?? ?? ?? 8d 8d ?? ?? ff ff 6a 6f 51 ff 15 ?? ?? ?? ?? 8d 95 ?? ?? ff ff 6a 7b}  //weight: 2, accuracy: Low
        $x_1_3 = "<!--Iniciop-->" wide //weight: 1
        $x_1_4 = "<!--Finp-->" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

