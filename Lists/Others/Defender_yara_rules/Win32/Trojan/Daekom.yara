rule Trojan_Win32_Daekom_B_2147621092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daekom.B"
        threat_id = "2147621092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daekom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "71"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "ping -n 5 127.0.0.1" ascii //weight: 10
        $x_10_3 = "DelSelf.bat" ascii //weight: 10
        $x_10_4 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 77 62 65 6d 5c [0-8] 2e 69 6e 69}  //weight: 10, accuracy: Low
        $x_10_5 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 77 62 65 6d 5c [0-8] 2e 73 79 73}  //weight: 10, accuracy: Low
        $x_10_6 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 77 62 65 6d 5c [0-8] 2e 64 6c 6c}  //weight: 10, accuracy: Low
        $x_10_7 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c [0-8] 2e 64 61 74}  //weight: 10, accuracy: Low
        $x_1_8 = "Isurium Brigantium" ascii //weight: 1
        $x_1_9 = "{01196771-F5D0-4549-9A91-BA1B0D9FD73E}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

