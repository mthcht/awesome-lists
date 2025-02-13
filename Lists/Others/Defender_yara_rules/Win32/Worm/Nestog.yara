rule Worm_Win32_Nestog_A_2147697469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nestog.A"
        threat_id = "2147697469"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nestog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 46 32 c1 88 07 47 49 0b c9 75 f3}  //weight: 1, accuracy: High
        $x_1_2 = {eb 0c 43 3a 5c 67 68 6f 73 74 79 2e 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

