rule Backdoor_Win32_Jabbroot_A_2147679358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Jabbroot.A"
        threat_id = "2147679358"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Jabbroot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 69 6e 64 6f 77 73 00 6d 65 73 73 61 67 65 54 65 73 74 00 62 6f 74 00 63 6c 69 65 6e 74}  //weight: 2, accuracy: High
        $x_1_2 = "/path/to/cacert.crt" ascii //weight: 1
        $x_1_3 = "ill process" ascii //weight: 1
        $x_1_4 = "ate cmd shell" ascii //weight: 1
        $x_1_5 = "ady exists!Upload file smaller than the existing file~" ascii //weight: 1
        $x_1_6 = "ote file size is less than the local file size has been!" ascii //weight: 1
        $x_1_7 = "oes not exist or is unreadable!" ascii //weight: 1
        $x_1_8 = "ile Abrot!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

