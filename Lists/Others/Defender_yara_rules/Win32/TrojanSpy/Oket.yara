rule TrojanSpy_Win32_Oket_A_2147627124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Oket.gen!A"
        threat_id = "2147627124"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Oket"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "65"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {56 52 49 57 5a 44 55 48 5f 50 6c 66 75 72 76 72 69 77 5f 5a 6c 71 67 72 7a 76 5f 46 78 75 75 68 71 77 59 68 75 76 6c 72 71 5f 55 78 71 00 00}  //weight: 20, accuracy: High
        $x_20_2 = "Uqhvyctg^Oketquqhv^Cevkxg Ugvwr^Kpuvcnngf Eqorqpgpvu^" ascii //weight: 20
        $x_20_3 = {4d 41 43 20 41 64 64 72 65 73 73 3a 20 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 0d 0a 00}  //weight: 20, accuracy: High
        $x_5_4 = {55 70 64 61 74 65 20 70 61 72 61 20 73 75 63 65 73 73 21 00 63 3a 5c 62 73 6c 6f 67 2e 74 78 74}  //weight: 5, accuracy: High
        $x_5_5 = {55 70 64 61 74 65 20 70 61 72 61 20 66 61 69 6c 65 64 21 00 63 3a 5c 62 73 6c 6f 67 2e 74 78 74}  //weight: 5, accuracy: High
        $x_1_6 = "{665DEE32/EW3E/98ff/085E/DE4EE2521526}" ascii //weight: 1
        $x_1_7 = "{539FF4GG/H6C7/64ff/067G/DE6C9E521526}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

