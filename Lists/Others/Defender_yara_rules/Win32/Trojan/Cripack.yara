rule Trojan_Win32_Cripack_PGCP_2147963150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cripack.PGCP!MTB"
        threat_id = "2147963150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cripack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {73 73 77 78 75 6d 73 76 6f 6c 00 00 46 79 57 6a 61 43 68 00 55 44 55 68 4a 61 66 73 43 4a 43 00 6b 6f 6f 79 44 72 56 00 55 4f 51 44 4c 6d 64 59 42 68 00 00 44 79 73 6b 48 65 45 73 45 6b 00 00 4e 61 6d 62 49 49 6f 61 74 00 00 00 67 6e 41 79 69 42 59 66 67 00 00 00 45 4a 72 45 58 69 78 42 79 00 00 00 4d 74 56 51 44 4d 50 00 55 45 67 63 58 63 56 75 43 00 00 00 4f 67 45 6d 6a 79 49 4b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

