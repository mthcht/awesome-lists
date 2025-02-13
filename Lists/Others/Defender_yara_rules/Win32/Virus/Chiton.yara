rule Virus_Win32_Chiton_A_2147606623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Chiton.gen!A"
        threat_id = "2147606623"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Chiton"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 81 3f 4d 5a 75 0b 8b 77 3c 03 f7 ad 05 b0 ba ff ff c3}  //weight: 1, accuracy: High
        $x_1_2 = {68 72 75 67 3e 68 20 3c 53 68 68 72 67 62 21 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

