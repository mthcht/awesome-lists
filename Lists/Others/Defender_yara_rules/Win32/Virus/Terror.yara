rule Virus_Win32_Terror_G_2147600246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Terror.G"
        threat_id = "2147600246"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Terror"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 81 e9 05 20 40 00 51 5d 8b f5 83 fe 00 74 28 90 90 90 90 68 4d 07 00 00 8d 8d 43 20 40 00 5a 66 8b 19 66 03 9d 05 20 40 00 66 f7 d3 66 89 19 83 c1 02 83 ea 01 75 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

