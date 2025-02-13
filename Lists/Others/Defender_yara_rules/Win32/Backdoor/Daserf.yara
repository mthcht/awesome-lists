rule Backdoor_Win32_Daserf_A_2147605574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Daserf.A"
        threat_id = "2147605574"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Daserf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {7e 1f 8a 45 10 b1 03 56 8b 75 0c f6 e9 8b 4d 08 2b ce 8a 14 31 32 55 10 2a d0 88 16 46 4f 75 f2}  //weight: 3, accuracy: High
        $x_3_2 = {3b d7 76 11 81 3c 0e 33 c0 56 a3 8d 04 0e 74 05 46 3b f2 72 ef 8b 78 18 53}  //weight: 3, accuracy: High
        $x_1_3 = "t0=%s&t1=" ascii //weight: 1
        $x_1_4 = "pinfs.dat" ascii //weight: 1
        $x_1_5 = "*FILELIST*" ascii //weight: 1
        $x_1_6 = "Inject Process:%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

