rule Trojan_Win32_Eepal_A_2147651209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eepal.A"
        threat_id = "2147651209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eepal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 65 67 69 6e 69 [0-16] 63 3a 5c 74 65 6d 70 2e 74 78 74 [0-16] 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 [0-16] 5c 52 65 63 79 63 6c 65 64}  //weight: 2, accuracy: Low
        $x_2_2 = "\\autorun.inf\\SpiderNt.exe" ascii //weight: 2
        $x_1_3 = "userinit.exe,C:\\Recycled\\Recycled.exe" ascii //weight: 1
        $x_1_4 = {63 68 65 61 6b 5f 68 6f 6f 6b 2e 64 6c 6c [0-16] 53 4f 46 54 57 41 52 45 5c 54 45 4e 43 45 4e 54 5c 51 51 5c}  //weight: 1, accuracy: Low
        $x_1_5 = {5b 43 41 50 53 5d [0-5] 5b 45 53 43 5d [0-5] 5b 50 47 55 50 5d [0-5] 5b 50 47 44 4e 5d [0-5] 5b 45 4e 44 5d [0-5] 5b 48 4f 4d 45 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

