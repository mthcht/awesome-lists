rule Worm_Win32_Metal_A_2147682511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Metal.A"
        threat_id = "2147682511"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Metal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HACKERS UNITED" wide //weight: 1
        $x_1_2 = "shell\\buscar=&JOSFRES" wide //weight: 1
        $x_1_3 = {61 75 74 6f 72 75 6e 43 [0-8] 52 45 47 49 53 54 52 41 52 5f 56 49 52 55 53 [0-8] 66 69 72 6d 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

