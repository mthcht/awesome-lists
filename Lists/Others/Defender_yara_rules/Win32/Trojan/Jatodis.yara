rule Trojan_Win32_Jatodis_A_2147656117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jatodis.gen!A"
        threat_id = "2147656117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jatodis"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 73 3c 03 f3 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 3f 0f be 00 33 f8 8d 4d ?? 57 53 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = "/js/data/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

