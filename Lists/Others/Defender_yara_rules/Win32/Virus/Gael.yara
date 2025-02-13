rule Virus_Win32_Gael_C_2147601512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Gael.C"
        threat_id = "2147601512"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Gael"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 80 00 00 00 58 ff d0 55 56 57 8b 43 3c 8d 74 03 78 ad ff 36 01 d8 50 8b 48 18 8b 68 20 01 dd e3 5c 49 8b 74 8d 00 01 de 31 ff 31 c0 ac 38 e0 74 07 c1 cf 0d 01 c7 eb f2 39 d7 75 e3 5d 8b 55 24 01 da 66 8b 0c 4a 8b 55 1c 01 da 8b 04 8a 01 d8 59 50 29 e8 39 c8 58 77 27 96 83 ec 40 89 e7 aa ac 3c 2e 75 fa}  //weight: 1, accuracy: High
        $x_1_2 = "hicumhgaelT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Gael_A_2147602885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Gael.gen!A"
        threat_id = "2147602885"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Gael"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 45 54 20 2f 76 78 39 2f 64 6c 2e 65 78 65 [0-18] 48 54 54 50 2f 31 2e 31 [0-18] 48 6f 73 74 3a [0-18] 75 74 65 6e 74 69 2e 6c 79 63 6f 73 2e 69 74}  //weight: 1, accuracy: Low
        $x_1_2 = {68 69 63 75 6d 68 67 61 65 6c 54 52 52 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

