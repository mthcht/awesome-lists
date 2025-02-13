rule Worm_Win32_Pemtaka_A_2147710918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pemtaka.A"
        threat_id = "2147710918"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pemtaka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c aa 75 0e 83 ef 32 83 c3 32 81 ff 2f f8 ff ff 7f}  //weight: 1, accuracy: High
        $x_1_2 = "__C4A38EF4_2234_4035_B1D4_8BA0D4182180__" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

