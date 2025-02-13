rule Worm_Win32_Umbex_A_2147682751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Umbex.A"
        threat_id = "2147682751"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Umbex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {62 61 74 2e 62 61 74 00}  //weight: 5, accuracy: High
        $x_5_2 = {6b 65 79 2e 72 65 67 00}  //weight: 5, accuracy: High
        $x_1_3 = "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System]" ascii //weight: 1
        $x_1_4 = "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

