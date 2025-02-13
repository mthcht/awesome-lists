rule Virus_Win32_Mabezat_2147601561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Mabezat"
        threat_id = "2147601561"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Mabezat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 81 ec d8 06 00 00 53 56 57 (b8 ?? ?? ?? ?? b9 00 00|b9 00 00 00 00 b8 ?? ?? ?? ??) 8a ?? 80 ?? ?? 88 ?? 83 ?? 01 83 ?? 01 81 f9 90 05 00 00 75 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

