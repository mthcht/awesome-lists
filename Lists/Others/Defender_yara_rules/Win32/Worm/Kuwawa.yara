rule Worm_Win32_Kuwawa_A_2147688804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kuwawa.A"
        threat_id = "2147688804"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kuwawa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5b 41 75 74 6f 52 75 6e [0-6] 61 [0-6] 5c 61 75 74 6f 72 75 6e 2e 69 6e 66}  //weight: 1, accuracy: Low
        $x_1_2 = {25 73 5c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 2e 65 78 65 [0-6] 6f 70 65 6e [0-6] 65 78 70 6c 6f 72 65}  //weight: 1, accuracy: Low
        $x_1_3 = "shell\\Open\\command=System_Volume_Information\\_restore{26864C17-18DD-4561-8410}\\driver.exe -o" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

