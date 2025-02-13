rule Trojan_Win32_Scotter_A_2147727796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scotter.A!bit"
        threat_id = "2147727796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scotter"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 8b f0 68 00 10 00 00 8d 46 01 50 6a 00 ff 15 ?? ?? ?? 00 56 8b f8 68 80 ?? ?? 00 57 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {00 55 46 6c 4a 53 55 6c 4a 53 55 6c 4a 53 55 6c 4a 53 55 6c 4a 53 55 6c 4a 4e 31 46 61 61 6b 46 59 55 44 42 42 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

