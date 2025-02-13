rule Backdoor_Win32_R2d2_A_2147650308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/R2d2.A"
        threat_id = "2147650308"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "R2d2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fe ff 74 15 ff 15 ?? ?? ?? ?? 3d b7 00 00 00 74 08 84 db 75 04 b3 01 eb 02 32 db 8b 57 04 56 6a 00 6a 00 6a 06 52 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "C3PO-r2d2-POE" ascii //weight: 1
        $x_1_3 = "\\\\.\\pipe\\sapipipe" ascii //weight: 1
        $x_1_4 = "SYS!IPC!" ascii //weight: 1
        $x_1_5 = "\\\\.\\KeyboardClassC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_R2d2_A_2147650308_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/R2d2.A"
        threat_id = "2147650308"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "R2d2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1b c0 25 da ff f2 ff 05 3f 00 0f 00 50 6a 00 51 52 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {1b c9 8d 44 24 04 81 e1 da ff f2 ff 50 8b 44 24 10 56 81 c1 3f 00 0f 00 6a 00 51 6a 00 6a 00 6a 00 52 50 ff 15}  //weight: 5, accuracy: High
        $x_1_3 = {44 55 4d 4d 59 21 44 55 4d 4d 59 00}  //weight: 1, accuracy: High
        $x_1_4 = "msnmsgr.exe" ascii //weight: 1
        $x_1_5 = "SkypePM.exe" ascii //weight: 1
        $x_1_6 = "yahoomessenger.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

