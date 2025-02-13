rule Trojan_Win32_Cloptern_A_2147725808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cloptern.A!dha"
        threat_id = "2147725808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cloptern"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 7d ec 00 74 47 6a 01 6a 00 6a 00 8d 55}  //weight: 2, accuracy: High
        $x_1_2 = "airplugin*.dat" ascii //weight: 1
        $x_1_3 = ",start1 /exc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Cloptern_B_2147725809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cloptern.B!dha"
        threat_id = "2147725809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cloptern"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 11 6a 05 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 5b 01 00 00 b8 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? b8 01 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = ",start1 /exc" ascii //weight: 1
        $x_1_3 = {50 72 6f 6a 65 63 74 31 2e 63 70 6c 00 73 74 61 72 74 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

