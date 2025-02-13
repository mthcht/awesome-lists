rule Trojan_Win32_Spyload_A_2147624394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spyload.A"
        threat_id = "2147624394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spyload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {79 73 70 79 6c 6f 61 64 65 72 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_3 = "mehrdad.dat" ascii //weight: 1
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

