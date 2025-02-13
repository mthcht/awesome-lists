rule Trojan_Win32_Screud_A_2147678395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Screud.A"
        threat_id = "2147678395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Screud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 01 0f b6 1e 8b d0 c1 ea 18 33 d3 0f b6 59 07 c1 e0 08 0b c3 c1 e2 02 33 82 ?? ?? ?? ?? 46 89 01 8b 41 04 c1 e0 08 33 82 ?? ?? ?? ?? 4f 89 41 04}  //weight: 3, accuracy: Low
        $x_5_2 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" wide //weight: 5
        $x_5_3 = "\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)" wide //weight: 5
        $x_1_4 = "EnableEUDC" ascii //weight: 1
        $x_1_5 = "guard32.dll" wide //weight: 1
        $x_1_6 = "wl_hook.dll" wide //weight: 1
        $x_1_7 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 30 00 78 00 30 00 30 00 00 00 69 00 6e 00 66 00 6f 00 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: High
        $x_1_8 = "unattend.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

