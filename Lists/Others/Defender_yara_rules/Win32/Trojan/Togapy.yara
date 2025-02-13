rule Trojan_Win32_Togapy_A_2147711336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Togapy.A!bit"
        threat_id = "2147711336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Togapy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WebDownFileFlood" ascii //weight: 1
        $x_1_2 = {8b 44 24 08 8a ca 03 c6 32 08 02 ca 46 3b 74 24 0c 88 08}  //weight: 1, accuracy: High
        $x_1_3 = {8a 4d 13 fe 4d ff 32 4d ff 88 4d 13 59 8a 4d 13 42 3b 55 0c 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

