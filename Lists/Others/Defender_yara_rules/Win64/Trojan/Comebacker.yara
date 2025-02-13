rule Trojan_Win64_Comebacker_A_2147773228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Comebacker.A.gen!dha"
        threat_id = "2147773228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Comebacker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 fb ff ff ff eb 1b b8 fb ff ff ff 41 bd 01 00 00 00 85 c9 44 0f 45 e8 41 8b c5 eb 05 b8 fd ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 4d e0 ff 55 d8 33 c0 eb 05 b8 fc ff ff ff 4c 8d 9c 24 80 00 00 00 49 8b 5b 10 49 8b 7b 18 49 8b e3 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

