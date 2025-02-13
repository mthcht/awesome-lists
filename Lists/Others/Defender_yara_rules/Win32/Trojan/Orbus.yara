rule Trojan_Win32_Orbus_A_2147687984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Orbus.A"
        threat_id = "2147687984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Orbus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LmNwbA==" wide //weight: 1
        $x_1_2 = "WFAtNjQ=" wide //weight: 1
        $x_1_3 = "YzpcRGVzY3JpdGlvblxMb2dz" wide //weight: 1
        $x_1_4 = "ZGVsIFNUUlRfRy5iYXQ=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Orbus_D_2147689344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Orbus.D"
        threat_id = "2147689344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Orbus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 61 6d 65 32 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 65 62 57 58 43 43 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 65 62 44 6f 77 6e 46 69 6c 65 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 49 59 54 43 50 46 6c 6f 6f 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "Defghijk Mnopqrstu" ascii //weight: 1
        $x_1_6 = {25 64 2a 25 64 4d 48 7a 00 00 00 00 7e 4d 48 7a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

