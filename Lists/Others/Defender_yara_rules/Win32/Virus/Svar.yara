rule Virus_Win32_Svar_A_2147653715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Svar.A"
        threat_id = "2147653715"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Svar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c8 90 02 00 8b fc 54 50 ff 56 0c 95 33 db 60 53 53 6a 03 53 53 6a 03 8d 57 2c 52 ff 56 14 50 50 53 53 8b 6f 20 55 50 53 81 c5 00 20 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

