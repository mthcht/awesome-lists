rule Ransom_Win64_StormEncryptor_PAA_2147975760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/StormEncryptor.PAA!MTB"
        threat_id = "2147975760"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "StormEncryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FileEncryptor-v5-hybrid" ascii //weight: 2
        $x_1_2 = "!!!README_FIRST!!!.txt" ascii //weight: 1
        $x_1_3 = "Mode 2: Multi-threaded (%d worker thread(s)). Scanning..." ascii //weight: 1
        $x_2_4 = "Storm Encryptor - Encrypt all files using Keyber Algorithm " ascii //weight: 2
        $x_1_5 = "Skipped extensions: .exe  .dll  .lnk" ascii //weight: 1
        $x_2_6 = "No -v, -sd: runs silently in background and self delete after finish" ascii //weight: 2
        $x_1_7 = "vssadmin delete shadows /All /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_StormEncryptor_A_2147975806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/StormEncryptor.A"
        threat_id = "2147975806"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "StormEncryptor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 74 6f 72 6d 20 45 6e 63 72 79 70 74 6f 72 20 2d 20 45 6e 63 72 79 70 74 20 61 6c 6c 20 66 69 6c 65 73 20 75 73 69 6e 67 20 4b 65 79 62 65 72 20 41 6c 67 6f 72 69 74 68 6d 20 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 6f 64 65 20 31 3a 20 53 63 61 6e 6e 69 6e 67 20 66 69 6c 65 73 2e 2e 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {21 21 21 52 45 41 44 4d 45 5f 46 49 52 53 54 21 21 21 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 6f 64 65 20 32 3a 20 4d 75 6c 74 69 2d 74 68 72 65 61 64 65 64 20 28 25 64 20 77 6f 72 6b 65 72 20 74 68 72 65 61 64 28 73 29 29 2e 20 53 63 61 6e 6e 69 6e 67 2e 2e 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 6f 6e 65 2e 20 45 6e 63 72 79 70 74 65 64 20 25 6c 6c 64 20 66 69 6c 65 28 73 29 2e 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

