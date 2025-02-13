rule Trojan_Win32_Delbat_B_2147624431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delbat.B"
        threat_id = "2147624431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delbat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 70 65 6e 00 73 65 6c 66 64 65 6c 00 2e 62 61 74}  //weight: 1, accuracy: High
        $x_1_2 = "del C:\\windows\\system32 *.dll /q" ascii //weight: 1
        $x_1_3 = "del C:\\windows\\system32 *.sys /q" ascii //weight: 1
        $x_1_4 = "ShellExecuteA" ascii //weight: 1
        $x_1_5 = "Purple Jumpers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

