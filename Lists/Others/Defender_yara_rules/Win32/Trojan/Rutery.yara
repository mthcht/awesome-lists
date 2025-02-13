rule Trojan_Win32_Rutery_A_2147689597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rutery.A"
        threat_id = "2147689597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rutery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 05 30 80 40 00 00 00 00 00 89 5c 24 04 c7 04 24 ?? ?? ?? ?? e8 c0 e8 ff ff 81 3d 30 80 40 00 95 5f 00 00 7e da}  //weight: 5, accuracy: Low
        $x_5_2 = {89 c1 c1 e9 10 a9 80 80 00 00 0f 44 c1 8d 4a 02 0f 44 d1 00 c0 83 da 03 66 c7 02 ?? ?? 89 da 8b 0a}  //weight: 5, accuracy: Low
        $x_2_3 = "ultimate-recovery.pl" ascii //weight: 2
        $x_2_4 = "libTUR.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

