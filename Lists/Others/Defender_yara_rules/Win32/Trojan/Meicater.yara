rule Trojan_Win32_Meicater_A_2147709859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meicater.A!bit"
        threat_id = "2147709859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meicater"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 73 00 79 00 73 00 00 00 72 00 62 00 00 00 77 00 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 3b 85 ?? ?? ?? ?? 8d 14 08 74 ?? 31 14 83 40 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

