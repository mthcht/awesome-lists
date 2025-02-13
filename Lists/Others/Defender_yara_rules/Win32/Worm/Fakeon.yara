rule Worm_Win32_Fakeon_A_2147708749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Fakeon.A!bit"
        threat_id = "2147708749"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakeon"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_2 = "1sass.exe" wide //weight: 2
        $x_2_3 = "New Folder.exe" wide //weight: 2
        $x_1_4 = "HideFileExt" wide //weight: 1
        $x_1_5 = "Hideprocess" wide //weight: 1
        $n_100_6 = "Autor David Farji - Concepto 201" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

