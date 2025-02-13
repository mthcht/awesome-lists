rule Backdoor_Win32_Linfo_A_2147663054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Linfo.A"
        threat_id = "2147663054"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Linfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d f4 03 7d f8 8a 07 c0 c8 05 34 21 88 07 41 3b ce 89 4d f8 7c e9}  //weight: 1, accuracy: High
        $x_1_2 = {5c 74 70 2e 64 61 74 00 00 00 65 78 46 6f 72 6d 00 00 6c 69 6e 6b 69 6e 66 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Linfo_A_2147663054_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Linfo.A"
        threat_id = "2147663054"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Linfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s\\smerp0.dbl" ascii //weight: 1
        $x_1_2 = "POST http://%s:%s/bks.asp" ascii //weight: 1
        $x_1_3 = {c7 45 e0 4a 53 50 72 c7 45 e4 6f 78 79 2e c7 45 e8 64 6c 6c 00 c7 45 ec 00 00 00 00 8d 75 e0 56 8b 5d b4 8d 93 ?? ?? ?? ?? b8 a4 00 00 00 03 d0 ff 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

