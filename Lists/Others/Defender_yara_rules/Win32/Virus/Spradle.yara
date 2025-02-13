rule Virus_Win32_Spradle_A_2147600233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Spradle.A"
        threat_id = "2147600233"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Spradle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 70 72 65 61 64 6c 6c 2e 64 6c 6c 00 00 00 00 50 61 79 4c 6f 61 64 00 38 00 28 ?? ?? ?? 00 00 00 00 00 00 00 00 38 ?? ?? ?? 30 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 46 ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

