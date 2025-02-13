rule Trojan_Win32_Wecorl_A_2147615813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wecorl.gen!A"
        threat_id = "2147615813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wecorl"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 0c 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65 00 5e}  //weight: 1, accuracy: High
        $x_1_2 = {e8 10 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65 20 2a 43 65 00 90 ff 17}  //weight: 1, accuracy: High
        $x_1_3 = {e8 09 00 00 00 6e 74 66 73 2e 73 79 73 00 [0-1] ff d6}  //weight: 1, accuracy: Low
        $x_1_4 = {e8 18 00 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 44 72 6d 5c 00 68 02 00 00 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

