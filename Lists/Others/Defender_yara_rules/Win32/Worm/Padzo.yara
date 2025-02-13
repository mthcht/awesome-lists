rule Worm_Win32_Padzo_A_2147682512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Padzo.A"
        threat_id = "2147682512"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Padzo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 00 45 00 6e 00 74 00 65 00 72 00 5d 00 [0-10] 5b 00 54 00 61 00 62 00 5d 00 [0-10] 5b 00 45 00 73 00 63 00 5d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "taskkill /im AntiLogger" wide //weight: 1
        $x_1_3 = {4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 3c 00 6d 00 79 00 65 00 6d 00 61 00 69 00 6c 00 40 00 6d 00 79 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 3e 00 [0-8] 46 00 72 00 6f 00 6d 00 [0-8] 6c 00 6f 00 67 00 6c 00 61 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

