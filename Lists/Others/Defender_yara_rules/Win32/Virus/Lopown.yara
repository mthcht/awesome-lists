rule Virus_Win32_Lopown_A_2147624211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Lopown.gen!A"
        threat_id = "2147624211"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Lopown"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb 32 54 76 98 39 9d 88 fe ff ff 0f 84 65 02 00 00 81 bd 80 fe ff ff 50 45 00 00 0f 85 55 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8d 45 c8 6a 28 50 80 4d ef c0 ff 75 fc ff 75 0c 56 e8}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 c8 2e 76 69 72 8d 59 ff c7 45 cc 75 73 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 ec 20 00 00 e0 6a 28 40 89 45 dc 8b 45 f4}  //weight: 1, accuracy: High
        $x_1_5 = {ff 75 10 ff 75 0c ff 56 10 8d 45 10 6a 00 50 ff 75 18 ff 75 14 ff 75 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

