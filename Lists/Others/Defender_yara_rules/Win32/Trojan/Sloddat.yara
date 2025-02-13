rule Trojan_Win32_Sloddat_A_2147685288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sloddat.A"
        threat_id = "2147685288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sloddat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 05 00 00 00 e8 fe a1 fd ff 83 f8 05 0f 87 07 01 00 00 ff 24 85 62 8e 42 00}  //weight: 1, accuracy: High
        $x_1_2 = {b8 df 00 00 00 e8 36 04 fe ff 3d df 00 00 00 0f 87 25 1e 00 00 ff 24 85 2c 2c 42 00}  //weight: 1, accuracy: High
        $x_1_3 = {c1 e2 02 52 ba 77 00 00 00 59 2b d1 88 50 01 c6 00 01 8d 95 4c fd ff ff 8d 85 50 fd ff ff b1 02}  //weight: 1, accuracy: High
        $x_2_4 = {72 65 74 2c 64 2b 77 6f 32 72 68 63 64 2b 71 5f 69 65 6e 5e 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

