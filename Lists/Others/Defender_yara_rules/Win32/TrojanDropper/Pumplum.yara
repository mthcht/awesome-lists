rule TrojanDropper_Win32_Pumplum_B_2147626747_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Pumplum.B"
        threat_id = "2147626747"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Pumplum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5c 00 6d 00 73 00 70 00 75 00 6d 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 5c 00 73 00 6c 00 75 00 6d 00 2e 00 62 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_2_3 = {c6 44 24 22 4d c6 44 24 23 5a ff 15 ?? ?? ?? ?? 8b f0 83 fe ff 75 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

