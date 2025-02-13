rule Trojan_Win32_Lnkhyd_A_2147630366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lnkhyd.A"
        threat_id = "2147630366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lnkhyd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 05 bb 01 00 00 00 [0-3] e8 ?? ?? ?? ?? 8b 55 [0-5] 8a 54 32 ff [0-5] 8a 4c 19 ff 32 d1 88 54 30 ff 43 46 4f 75}  //weight: 2, accuracy: Low
        $x_2_2 = {ba 37 00 00 00 e8 ?? ?? ?? ?? b8 [0-9] ba 0c 00 00 00 e8}  //weight: 2, accuracy: Low
        $x_1_3 = {2a 2e 6c 6e 6b [0-16] 7b 70 66 6d 7d [0-16] 7b 64 73 6b 7d}  //weight: 1, accuracy: Low
        $x_1_4 = {52 4e 44 3d ?? 3b 48 4f 53 54 3d [0-16] 3b 3b 4d 41 43 3d}  //weight: 1, accuracy: Low
        $x_1_5 = {7b 71 6b 6d 7d [0-16] 51 51 2e 45 58 45 [0-16] 51 51 47 41 4d 45 2e 45 58 45 [0-16] 55 4e 49 4e 53 54 41 4c 4c 2e 45 58 45}  //weight: 1, accuracy: Low
        $x_1_6 = {7b 70 66 6d 7d [0-16] 7b 73 74 6d 7d [0-16] 7b 71 6b 6d 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

