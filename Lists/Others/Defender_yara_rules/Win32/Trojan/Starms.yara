rule Trojan_Win32_Starms_A_2147655189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Starms.A"
        threat_id = "2147655189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Starms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\MSoftware" wide //weight: 1
        $x_1_2 = "\\msftldr.dll,Install" wide //weight: 1
        $x_1_3 = {5c 00 6d 00 73 00 66 00 74 00 64 00 6d 00 2e 00 65 00 78 00 65 00 00 00 5c 00 6d 00 73 00 66 00 74 00 64 00 6d 00 33 00 32 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

