rule Trojan_Win32_Entebore_A_2147655791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Entebore.gen!A"
        threat_id = "2147655791"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Entebore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%REQKEY%" ascii //weight: 1
        $x_1_2 = {22 6a 73 22 3a 20 5b 20 22 25 43 53 46 49 4c 45 25 22 20 5d 2c 20 0a}  //weight: 1, accuracy: High
        $x_1_3 = {07 00 00 00 67 6f 6f 67 6c 65 2e 00 [0-8] 06 00 00 00 79 61 68 6f 6f 2e 00 [0-8] 05 00 00 00 62 69 6e 67 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

