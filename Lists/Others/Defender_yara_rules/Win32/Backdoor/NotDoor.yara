rule Backdoor_Win32_NotDoor_H_2147952091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NotDoor.H!dha"
        threat_id = "2147952091"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NotDoor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LoadMacroProviderOnBoot" wide //weight: 1
        $x_1_2 = "-enc " ascii //weight: 1
        $x_1_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 4f 00 66 00 66 00 69 00 63 00 65 00 5c 00 [0-8] 5c 00 4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00}  //weight: 1, accuracy: Low
        $x_1_4 = "SSPICLI" ascii //weight: 1
        $x_1_5 = "\\Options\\General" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

