rule Backdoor_Win32_Neporoot_A_2147679421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Neporoot.A"
        threat_id = "2147679421"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Neporoot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 3f 00 00 00 33 c0 8d 7c 24 ?? 8d 54 24 ?? f3 ab 66 ab aa bf ?? ?? ?? ?? 83 c9 ff 33 c0 53 f2 ae f7 d1 2b f9 8b c1 8b f7 8b fa 8d 54 24 ?? c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 f3 a4 8d bc 24}  //weight: 2, accuracy: Low
        $x_1_2 = ".ueopen.com/test.html" ascii //weight: 1
        $x_1_3 = "*(SY)# cmd" ascii //weight: 1
        $x_1_4 = "send = %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

