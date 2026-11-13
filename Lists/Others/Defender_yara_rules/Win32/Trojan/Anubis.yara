rule Trojan_Win32_Anubis_JH_2147982029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Anubis.JH"
        threat_id = "2147982029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Anubis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4e 6f 72 6c 69 6e 64 5c 43 6f 6e 66 69 67 53 79 6e 63 5c 50 72 6f 78 79 53 65 72 76 65 72 00}  //weight: 11, accuracy: High
        $x_11_2 = {25 4c 4f 43 41 4c 41 50 50 44 41 54 41 25 5c 4e 6f 72 6c 69 6e 64 5c 43 6f 6e 66 69 67 53 79 6e 63 5c 43 61 63 68 65 5c 00}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

