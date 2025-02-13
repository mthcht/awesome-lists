rule Worm_Win32_Jaakpol_A_2147626917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Jaakpol.A"
        threat_id = "2147626917"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaakpol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 6f 72 20 2f 72 20 22 ?? 3a 5c 22 20 25 25 61 20 69 6e 20 28 2a 2e 64 6f 63 20 2a 2e 74 78 74 20 2a 2e 65 78 63 65 6c 20 2a 2e 70 64 66 20 2a 2e 72 74 66 20 2a 2e 6a 70 67 20 2a 2e 68 74 6d 6c 20 2a 2e 7a 69 70 20 2a 2e 72 61 72 20 2a 2e 70 70 74 20 2a 2e 6d 70 33 20 2a 2e 33 67 70 20 2a 2e 61 76 69 20 2a 2e 77 6d 76 20 2a 2e 66 6c 76 20 2a 2e 6f 64 74 20 2a 2e 67 69 66 20 2a 2e 63 64 72 20 2a 2e 70 6e 67 20 2a 2e 69 63 6f 20 2a 2e 6d 70 34 20 2a 2e 62 6d 70 20 2a 2e 6d 70 67 20 2a 2e 6d 70 65 67 20 2a 2e 77 6d 61 20 2a 2e 64 61 74 29 20 64 6f 20 28 63 6f 70 79 20 25 30 20 22 25 25 7e 64 70 6e 61 2e 65 78 65 22 20 26 26 20 61 74 74 72 69 62 20 2b 73 20 2b 68 20 22 25 25 7e 66 61 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = "NET STOP MCSHIELD" ascii //weight: 1
        $x_1_3 = "%StpAV% Automatic Updates >nul & cls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

