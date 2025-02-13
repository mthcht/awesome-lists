rule Ransom_Win32_KeepLock_A_2147696433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KeepLock.A"
        threat_id = "2147696433"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KeepLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 41 00 70 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 00 72 00 79 00 70 00 74 00 6f 00 41 00 70 00 70 00 2d 00 31 00 2e 00 30 00 2d 00 45 00 76 00 65 00 6e 00 74 00 2d 00 53 00 74 00 61 00 72 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 43 72 79 70 74 6f 41 70 70 5c 62 75 69 6c 64 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 4b 65 65 70 41 6c 69 76 65 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 43 72 79 70 74 6f 41 70 70 5c 62 75 69 6c 64 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 53 65 6c 66 44 65 73 74 72 6f 79 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_KeepLock_A_2147696433_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/KeepLock.A"
        threat_id = "2147696433"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "KeepLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 69 74 63 6f 69 6e 5f 61 64 64 72 65 73 73 3d 25 73 26 65 6d 70 69 64 3d 25 73 26 63 6f 6d 70 3d 25 73 26 69 70 76 34 3d 25 73 26 62 6c 6b 6b 3d 25 73 26 70 75 62 6c 3d 25 73 26 70 72 69 76 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "Altrought it's may yet easy to buy Bitcoin," ascii //weight: 1
        $x_1_3 = "How can you decrypt your files</legend>" ascii //weight: 1
        $x_1_4 = {69 00 6d 00 6d 00 65 00 64 00 69 00 61 00 74 00 65 00 20 00 64 00 65 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 74 00 68 00 65 00 20 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 20 00 6b 00 65 00 79 00 20 00 62 00 79 00 20 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 00 74 00 6f 00 70 00 20 00 79 00 6f 00 75 00 72 00 20 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 21 00 21 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {54 00 6f 00 74 00 61 00 6c 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 66 00 69 00 6c 00 65 00 73 00 3a 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "Crypto.FileLocker" wide //weight: 1
        $x_1_8 = {6b 00 65 00 65 00 70 00 61 00 6c 00 69 00 76 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = "use it or goodbye forever!!!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

