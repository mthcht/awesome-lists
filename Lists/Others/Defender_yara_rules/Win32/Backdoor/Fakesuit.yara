rule Backdoor_Win32_Fakesuit_B_2147727833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Fakesuit.B"
        threat_id = "2147727833"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakesuit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\users\\mz\\documents\\visual studio 2013\\Projects\\Shellcode\\Release\\Shellcode.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

