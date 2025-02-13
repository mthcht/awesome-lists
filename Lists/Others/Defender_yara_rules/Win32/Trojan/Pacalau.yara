rule Trojan_Win32_Pacalau_Z_2147928661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pacalau.Z"
        threat_id = "2147928661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pacalau"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 63 00 61 00 6c 00 75 00 61 00 2e 00 65 00 78 00 65 00 [0-5] 2d 00 61 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 00 63 00 61 00 6c 00 75 00 61 00 2e 00 65 00 78 00 65 00 [0-5] 2d 00 61 00 [0-32] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {70 00 63 00 61 00 6c 00 75 00 61 00 2e 00 65 00 78 00 65 00 [0-5] 2d 00 61 00 [0-32] 2e 00 63 00 70 00 6c 00}  //weight: 1, accuracy: Low
        $n_100_4 = {70 00 63 00 61 00 6c 00 75 00 61 00 2e 00 65 00 78 00 65 00 [0-60] 20 00 2d 00 64 00}  //weight: -100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

