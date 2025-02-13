rule Worm_Win32_Eson_A_2147614559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Eson.A"
        threat_id = "2147614559"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Eson"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 73 72 73 73 00 61 73 64 61 73 64}  //weight: 10, accuracy: High
        $x_2_2 = "mira esta foto de mi hermana" wide //weight: 2
        $x_2_3 = "C:\\Todo\\W32-" wide //weight: 2
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_5 = {00 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

