rule Trojan_Win32_Mader_A_2147606638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mader.gen!A"
        threat_id = "2147606638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mader"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 80 3a 3e 75 45 80 7a 01 58 75 3f 80 7a 02 49 75 39 80 7a 03 54 75 33 8b 42 0c 85 c0 74 26 83 c0 ff 78 21}  //weight: 1, accuracy: High
        $x_1_2 = {81 39 75 73 65 64 75 18 85 c0 74 12 8b 71 0c 3b 70 0c 7c 0c 7f 08 8b 71 08 3b 70 08 76 02 8b c1 83 c1 5c 4a}  //weight: 1, accuracy: High
        $x_1_3 = {74 31 80 38 79 75 12 80 78 01 65 75 0c 80 78 02 73 75 06 89 7c 24 14 eb 1a 53 e8 ?? ?? ff ff 85 c0 59 75 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

