rule Trojan_Win32_Lnkiebes_A_2147641987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lnkiebes.A"
        threat_id = "2147641987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lnkiebes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {74 11 c7 45 ?? ?? ?? ?? ?? 68 a0 0f 00 00 e8 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 68 98 3a 00 00 e8}  //weight: 3, accuracy: Low
        $x_1_2 = "Internet Explorer.bestie" wide //weight: 1
        $x_1_3 = "\\$NtUninstallKB971000$\\sky.res ===" wide //weight: 1
        $x_1_4 = "bullsky.res" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lnkiebes_B_2147642380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lnkiebes.B"
        threat_id = "2147642380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lnkiebes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {08 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 08 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 08 00 00 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? 08 00 00 00 83 3d ?? ?? ?? ?? 00 74 58 8b 0d ?? ?? ?? ?? 66 83 39 01 75 4c}  //weight: 3, accuracy: Low
        $x_2_2 = "Internet Explorer.bestie" wide //weight: 2
        $x_1_3 = "\\WinRAR\\Formats\\KB" wide //weight: 1
        $x_1_4 = ".best360" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

