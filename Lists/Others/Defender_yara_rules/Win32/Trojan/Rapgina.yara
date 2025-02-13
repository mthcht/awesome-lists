rule Trojan_Win32_Rapgina_A_2147642572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rapgina.A"
        threat_id = "2147642572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rapgina"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WlxNegotiate" ascii //weight: 1
        $x_1_2 = "SPOOL\\DRIVERS\\COLOR\\faxmode.inc" ascii //weight: 1
        $x_1_3 = "Not Administrators Group User Logon" ascii //weight: 1
        $x_1_4 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 47 00 69 00 6e 00 61 00 44 00 4c 00 4c 00 00 00 4e 00 65 00 65 00 64 00 43 00 74 00 72 00 6c 00 41 00 6c 00 74 00 44 00 65 00 6c 00 00 00 00 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

