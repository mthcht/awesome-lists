rule Trojan_Win32_Cigril_B_2147849474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cigril.B!dha"
        threat_id = "2147849474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cigril"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "libremote.dat" wide //weight: 2
        $x_1_2 = {6c 69 62 63 75 72 6c [0-8] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e9 07 81 e1 01 01 01 01 44 6b d9 1b 41 8b ca 81 e1 7f 7f 7f ff 03 c9 44 33 d9}  //weight: 1, accuracy: High
        $x_1_4 = {8b 46 18 48 8d 4e 28 33 01 41 89 06 8b 46 2c 33 46 1c 41 89 46 04 8b 46 30 33 46 20 41 89 46 08 8b 46 34 33 46 24 41 89 46 0c 49 83 c6 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

