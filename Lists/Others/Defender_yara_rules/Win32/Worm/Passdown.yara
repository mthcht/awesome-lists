rule Worm_Win32_Passdown_2147605074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Passdown"
        threat_id = "2147605074"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Passdown"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Autorun.inf" ascii //weight: 1
        $x_1_2 = {4f 8d 4f 01 8a 47 01 47 84 c0 75 f8 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 07 a1 ?? ?? ?? ?? 89 57 04 8a 15 ?? ?? ?? ?? 89 47 08 8d 84 24 ?? ?? 00 00 50 51 88 57 0c ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

