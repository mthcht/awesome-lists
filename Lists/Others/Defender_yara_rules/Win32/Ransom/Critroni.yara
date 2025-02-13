rule Ransom_Win32_Critroni_A_2147688248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Critroni.A"
        threat_id = "2147688248"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Critroni"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 00 30 00 32 00 69 00 25 00 63 00 25 00 30 00 32 00 69 00 25 00 63 00 25 00 30 00 32 00 69 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "AllFilesAreLocked" wide //weight: 1
        $x_1_3 = {6b 65 79 3d 00 00 00 00 75 73 64 3d 00 00 00 00 61 64 64 72 65 73 73 3d 00 00 00 00 70 72 69 63 65 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d 61 69 6e 20 6c 6f 63 6b 65 72 20 77 69 6e 64 6f 77 2c 20 66 6f 6c 6c 6f 77 20 74 68 65 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 20 6f 6e 20 74 68 65 20 6c 6f 63 6b 65 72 2e 0d 0a 4f 76 65 72 77 69 73 65 2c}  //weight: 1, accuracy: High
        $x_1_5 = "%s%s.ctbl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Critroni_B_2147688844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Critroni.B"
        threat_id = "2147688844"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Critroni"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%f1%%c1%%key%%f0%%c0%" ascii //weight: 1
        $x_1_2 = "encrypted.%f0%%c0%" ascii //weight: 1
        $x_1_3 = "%a1%%f3%%c3%Test decryption.%f0%%c0%" ascii //weight: 1
        $x_1_4 = "%a1%%f3%%c3%Requesting private key.%f0%%c0%" ascii //weight: 1
        $x_1_5 = "AllFilesAreLocked" wide //weight: 1
        $x_1_6 = {6b 65 79 3d [0-8] 75 73 64 3d [0-12] 61 64 64 72 65 73 73 3d 00}  //weight: 1, accuracy: Low
        $x_1_7 = {62 74 63 70 72 69 63 65 [0-8] 75 73 64 70 72 69 63 65}  //weight: 1, accuracy: Low
        $x_1_8 = "POST /unlock HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Critroni_B_2147688848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Critroni.B!!Critroni.gen"
        threat_id = "2147688848"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Critroni"
        severity = "Critical"
        info = "Critroni: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%f1%%c1%%key%%f0%%c0%" ascii //weight: 1
        $x_1_2 = "encrypted.%f0%%c0%" ascii //weight: 1
        $x_1_3 = "%a1%%f3%%c3%Test decryption.%f0%%c0%" ascii //weight: 1
        $x_1_4 = "%a1%%f3%%c3%Requesting private key.%f0%%c0%" ascii //weight: 1
        $x_1_5 = "AllFilesAreLocked" wide //weight: 1
        $x_1_6 = "ctb2" wide //weight: 1
        $x_1_7 = {6b 65 79 3d [0-8] 75 73 64 3d [0-12] 61 64 64 72 65 73 73 3d 00}  //weight: 1, accuracy: Low
        $x_1_8 = {62 74 63 70 72 69 63 65 [0-8] 75 73 64 70 72 69 63 65}  //weight: 1, accuracy: Low
        $x_1_9 = "POST /unlock HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Critroni_C_2147694931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Critroni.C"
        threat_id = "2147694931"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Critroni"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 29 8b 55 ?? 89 d0 c1 e0 02 01 d0 d1 e0 89 c2 8b 45 14 8b 08 8b 45 ?? 01 c8 8a 40 04 0f be c0 01 d0 83 e8 30 89 45 ?? ff 45 ?? 8b 45 14 8b 10 8b 45 ?? 01 d0 8a 40 04 84 c0 0f 95 c0 84 c0 75 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 2c 8b 55 f4 8b 45 08 8d 0c 02 8b 55 f4 8b 45 08 01 d0 8a 18 8b 45 f4 99 f7 7d 10 89 d0 89 c2 8b 45 0c 01 d0 8a 00 31 d8 88 01 ff 45 f4 8b 45 f4 3b 45 14 0f 9c c0 84 c0 75 c7 83 c4 (1c|2d|2c)}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 95 c0 ff 4d ?? 84 c0 75 ?? [0-64] b0 00 ba ?? 00 00 00 89 df 89 d1 f3 aa c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff ?? c6 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_3_4 = {0c 7d 37 8b 84 24 ?? ?? 00 00 0f be 84 04 ?? ?? 00 00 35 ?? (01|2d|ff) 00 00 88 c1 8b 84 24 ?? ?? 00 00 88 8c 04 ?? ?? 00 00 8b 84 24 ?? ?? 00 00 83 c0 01 89 84 24 ?? ?? 00 00 eb bf 8d 05 ?? ?? ?? (60|2d|6f) b9 (08|2d|1f) 00 00 00 [0-64] c7 84 24 ?? ?? 00 00 00 00 00 00 c7 84 24 ?? ?? 00 00 00 00 00 00 83 bc 24 ?? ?? 00 00 ?? 7d 37}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

