rule Worm_Win32_Hecsem_A_2147616934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hecsem.gen!A"
        threat_id = "2147616934"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hecsem"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 10, accuracy: High
        $x_1_2 = {3a 5c 68 6f 6f 6b 2e 64 6c 6c 00 ?? 3a 5c 73 6d 63 63 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "shellexecute=smcc.exe -autorun" ascii //weight: 1
        $x_1_4 = {73 6d 63 63 00 00 00 00 6e 6f 74 65 70 61 64 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

