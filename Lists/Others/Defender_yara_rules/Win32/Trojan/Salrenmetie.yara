rule Trojan_Win32_Salrenmetie_A_2147681815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salrenmetie.gen!A"
        threat_id = "2147681815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salrenmetie"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 08 89 45 fc 8b 4d fc 83 c1 09 89 4d fc 8b 55 fc 83 c2 0a 89 55 fc 68 20 4e 00 00 ff 15 00 10 40 00 6a 00 ff 15 08 10 40 00 33 c0 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

