rule Worm_Win32_Nekav_C_2147635772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nekav.C"
        threat_id = "2147635772"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nekav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 6f 6f 74 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00 4f 70}  //weight: 1, accuracy: High
        $x_1_2 = {43 31 4f 65 44 6d 38 31 36 57 37 4b 7a 4c 2f 4d 6e 36 57 63 36 55 46 00}  //weight: 1, accuracy: High
        $x_1_3 = {fe 45 ff 80 7d ff 5b 0f 85 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

