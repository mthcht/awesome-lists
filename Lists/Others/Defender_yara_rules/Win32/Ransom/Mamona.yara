rule Ransom_Win32_Mamona_CCJX_2147938504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mamona.CCJX!MTB"
        threat_id = "2147938504"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mamona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Mamona, R.I.P" ascii //weight: 2
        $x_1_2 = "cmd.exe /C ping 127.0.0.7 -n 3 > Nul & Del /f /q \"%s\"" wide //weight: 1
        $x_1_3 = "YOUR FILES HAVE BEEN ENCRYPTED!" wide //weight: 1
        $x_1_4 = "CHECK README." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mamona_DA_2147941222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mamona.DA!MTB"
        threat_id = "2147941222"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mamona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "your files have been encrypted" ascii //weight: 10
        $x_5_2 = "README.HAes.txt" ascii //weight: 5
        $x_5_3 = ".HAES" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mamona_AB_2147951431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mamona.AB!MTB"
        threat_id = "2147951431"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mamona"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a bd 6d 10 00 00 0f 94 45 ec 80 3d c4 6e 43 00 00 88 45 d2 8a 85 6f 10 00 00 88 45 d1 8a 85 71 10 00 00 88 45 c0 8a 85 73 10 00 00 88 45 b0 88 5d a0 74 22 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mamona_A_2147961265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mamona.A"
        threat_id = "2147961265"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mamona"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 00 61 00 72 00 6e 00 69 00 6e 00 67 00 3a 00 20 00 42 00 6f 00 74 00 68 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 61 00 6e 00 64 00 20 00 68 00 61 00 73 00 68 00 20 00 70 00 72 00 6f 00 76 00 69 00 64 00 65 00 64 00 2e 00 20 00 48 00 61 00 73 00 68 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 75 00 73 00 65 00 64 00 20 00 66 00 69 00 72 00 73 00 74 00 2c 00 20 00 74 00 68 00 65 00 6e 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 61 6d 6f 6e 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {70 00 72 00 69 00 6e 00 74 00 65 00 64 00 20 00 6e 00 6f 00 74 00 65 00 20 00 74 00 6f 00 20 00 70 00 72 00 69 00 6e 00 74 00 65 00 72 00 3a 00 20 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {59 00 4f 00 55 00 52 00 20 00 46 00 49 00 4c 00 45 00 53 00 20 00 48 00 41 00 56 00 45 00 20 00 42 00 45 00 45 00 4e 00 20 00 45 00 4e 00 43 00 52 00 59 00 50 00 54 00 45 00 44 00 21 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

