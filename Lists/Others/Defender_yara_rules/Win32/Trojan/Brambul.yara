rule Trojan_Win32_Brambul_A_2147705779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Brambul.A!dha"
        threat_id = "2147705779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Brambul"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 60 ea 00 00 77 34 6a 00 8d 04 1f}  //weight: 1, accuracy: High
        $x_1_2 = {f2 ae f7 d1 49 81 f9 f4 00 00 00 73 ?? 8b 04 16 33 d2 33 c9 8a 50 03}  //weight: 1, accuracy: Low
        $x_3_3 = {ff d3 8b f8 81 e7 ff 0f 00 00 ff d6 03 c7 33 d2 b9 ff 00 00 00 f7 f1 8b fa ff d3 8b d0 81 e2 ff 0f 00 00}  //weight: 3, accuracy: High
        $x_1_4 = {61 64 6d 69 6e 69 73 74 72 61 74 6f 72 00 00 00 25 64 2e 25 64 2e 25 64 2e 25 64 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

