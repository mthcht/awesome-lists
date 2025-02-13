rule Worm_Win32_Winlire_A_2147657809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Winlire.A"
        threat_id = "2147657809"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Winlire"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 77 69 6e 65 6c 69 72 00 5c 4d 79 5f 46 6f 74 6f 67 72 61 66 69 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 c7 43 10 38 00 ba ?? ?? ?? ?? 8d 45 e4 e8 ?? ?? ?? ?? ff 43 1c 33 c0 89 45 f8 8d 45 fc ff 43 1c 8d 55 e4 8d 4d f8 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {66 c7 43 10 14 00 8b f0 ba 02 00 00 80 8b c6 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

