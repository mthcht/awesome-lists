rule Trojan_Win32_Hecsem_A_2147616933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hecsem.gen!A"
        threat_id = "2147616933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hecsem"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = {68 6f 6f 6b 2e 64 6c 6c 00 45 6a 65 63 75 74 61 62 6c 65}  //weight: 1, accuracy: High
        $x_1_3 = {48 6f 6f 6b 4f 66 66 00 48 6f 6f 6b 4f 6e}  //weight: 1, accuracy: High
        $x_1_4 = "\\Shell\\Open\\Command" ascii //weight: 1
        $x_1_5 = {00 73 6d 63 63 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

