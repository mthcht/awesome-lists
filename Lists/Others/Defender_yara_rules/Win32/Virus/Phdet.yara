rule Virus_Win32_Phdet_A_2147684800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Phdet.A"
        threat_id = "2147684800"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Phdet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 24 06 00 00 89 4e 1c 81 fa 04 c0 22 00 74 27 bf 10 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {68 a3 6d 42 2a}  //weight: 1, accuracy: High
        $x_1_3 = {3d b1 1d 00 00 0f 8f ?? ?? ?? ?? 3d b0 1d 00 00 0f 8d ?? ?? ?? ?? 3d 28 0a 00 00 0f 84 ?? ?? ?? ?? 3d ce 0e 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

