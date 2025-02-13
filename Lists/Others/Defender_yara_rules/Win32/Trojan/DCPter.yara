rule Trojan_Win32_DCPter_A_2147649490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DCPter.gen!A"
        threat_id = "2147649490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DCPter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 68 79 73 69 63 61 6c 44 72 69 76 65 58 00 00 53 4f 46 54}  //weight: 1, accuracy: High
        $x_1_2 = {5c 53 59 53 54 45 4d 33 32 5c 44 52 49 56 45 52 53 5c 00 00 5c 3f 3f 5c}  //weight: 1, accuracy: High
        $x_1_3 = {53 61 74 79 61 6d 65 76 61 20 4a 61 79 61 74 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

