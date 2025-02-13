rule Virus_Win95_MrKlunky_A_2147606626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win95/MrKlunky.gen!A"
        threat_id = "2147606626"
        type = "Virus"
        platform = "Win95: Windows 95, 98 and ME platforms"
        family = "MrKlunky"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 7f 34 00 00 f7 bf 7c ca 8b 47 34 89 85 09 05 00 00 33 c0 66 8b 47 14 03 c7 83 c0 18 66 8b 4f 06 81 38 2e 65 64 61 75 09 81 78 04 74 61 00 00 74 10 83 c0 28 66 49 66 83 f9 00 75 e4 e9 7c 01 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {b9 e8 03 00 00 f2 ae 0b c9 0f 84 2c 02 00 00 81 7f fb 2e 45 58 45 0f 85 1f 02 00 00 b8 00 43 00 00 cd 20 32 00 40 00 0f 82 0e 02 00 00 51 b8 01 43 00 00 33 c9 cd 20 32 00 40 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\\\.\\MrKlunky.VxD" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\VxD\\MrKlunky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

