rule Trojan_Win32_Broperk_A_2147647879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Broperk.gen!A"
        threat_id = "2147647879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Broperk"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e8 20 8b df 33 d8 83 c3 20}  //weight: 1, accuracy: High
        $x_1_2 = {51 7d 79 73 23 76 7f 78 3b 73 6f 7d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

