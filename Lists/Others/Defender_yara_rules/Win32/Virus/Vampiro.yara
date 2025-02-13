rule Virus_Win32_Vampiro_A_2147632676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Vampiro.A"
        threat_id = "2147632676"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Vampiro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ff 00 00 00 aa b8 04 24 00 00 66 ab b8 ff 25 00 00 66 ab 8b 85 ?? ?? ?? ?? ab c3 19 00 8d bd ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? ab 8b f8 8b 9d ?? ?? ?? ?? 0b db 74 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

