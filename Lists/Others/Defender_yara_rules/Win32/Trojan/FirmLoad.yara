rule Trojan_Win32_FirmLoad_A_2147948094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FirmLoad.A!dha"
        threat_id = "2147948094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FirmLoad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {45 33 c9 45 33 c0 33 d2 b9 42 4d 53 52 ff 15}  //weight: 3, accuracy: High
        $x_1_2 = {ba 02 00 00 00 41 b8 00 00 00 10 ?? ?? ?? [0-3] ff 15 ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? [0-6] ba 02 00 00 00 41 b8 00 00 00 10 ?? ?? ?? [0-3] ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 0e 8b d1 8b c1 c1 e9 08 c1 e2 10 25 00 ff 00 00 81 e1 00 ff 00 00 0b d0 0f b6 46 03 c1 e2 08 0b d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

