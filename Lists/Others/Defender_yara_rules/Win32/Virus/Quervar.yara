rule Virus_Win32_Quervar_B_2147657615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Quervar.gen!B"
        threat_id = "2147657615"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Quervar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "[---qrnqyvar---]" ascii //weight: 1
        $x_1_2 = "[+++scarface+++]" ascii //weight: 1
        $x_1_3 = "[---deadline---]" ascii //weight: 1
        $x_10_4 = {03 cb 81 e1 ff 00 00 00 8b 1c 24 8a 1c 13 32 99 ?? ?? ?? ?? 8b 4c 24 04 88 1c 11 42 48 75 ad 59 5a 5f 5e 5b c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Virus_Win32_Quervar_B_2147657615_1
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Quervar.gen!B"
        threat_id = "2147657615"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Quervar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 02 8b ca 80 c1 bf 80 e9 0d 72 14 80 e9 0d 72 1f 80 c1 fa 80 e9 0d 72 07 80 e9 0d 72 12 eb 1e 81 e2 ff 00 00 00 83 c2 0d 8b 0b 88 14 01 eb 0e}  //weight: 1, accuracy: High
        $x_1_2 = {2d 00 6c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 00 00 59 00 62 00 6e 00 71 00 00 00 00 00 46 00 62 00 73 00 67 00 6a 00 6e 00 65 00 72 00 5c 00 5a 00 76 00 70 00 65 00 62 00 66 00 62 00 73 00 67 00 5c 00 4a 00 76 00 61 00 71 00 62 00 6a 00 66 00 20 00 41 00 47 00 5c 00 50 00 68 00 65 00 65 00 72 00 61 00 67 00 49 00 72 00 65 00 66 00 76 00 62 00 61 00 5c 00 4a 00 76 00 61 00 71 00 62 00 6a 00 66 00}  //weight: 1, accuracy: High
        $x_1_3 = {75 72 6c 6d 6f 6e 2e 64 6c 6c 00 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 57 00 00 68 00 74 00 74 00 70 00 00 00 00 00 3f 00 00 00 26 00 00 00 26 00 70 00 69 00 6e 00 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Quervar_D_2147682030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Quervar.gen!D"
        threat_id = "2147682030"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Quervar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 02 8b ca 80 c1 bf 80 e9 0d 72 14 80 e9 0d 72 1f 80 c1 fa 80 e9 0d 72 07 80 e9 0d 72 12 eb 1e 81 e2 ff 00 00 00 83 c2 0d 8b 0b 88 14 01 eb 0e}  //weight: 1, accuracy: High
        $x_1_2 = {36 69 73 74 33 39 66 69 75 38 72 6a 6f 00 00 00 2d 00 75 00 70 00 70 00 20 00 00 00 37 38 69 38 37 36 75 79 34 35 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

