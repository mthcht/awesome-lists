rule DoS_Win32_DragoWiper_C_2147944725_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/DragoWiper.C!dha"
        threat_id = "2147944725"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "DragoWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 49 4e 46 4f 5d 20 46 69 6c 65 20 64 61 74 61 20 72 65 61 64 20 69 6e 74 6f 20 6d 65 6d 6f 72 79 2e 20 52 65 61 64 20 73 69 7a 65 3a 20 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 45 52 52 4f 52 5d 20 46 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 65 6e 63 72 79 70 74 65 64 20 64 61 74 61 20 74 6f 20 66 69 6c 65 20 61 74 20 6f 66 66 73 65 74 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 72 6f 63 65 73 73 69 6e 67 20 6e 6f 6e 2d 73 79 73 74 65 6d 20 64 72 69 76 65 3a 20 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 6c 6c 20 64 72 69 76 65 73 20 70 72 6f 63 65 73 73 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21 00}  //weight: 1, accuracy: High
        $x_1_5 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 66 00 69 00 6c 00 65 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 64 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule DoS_Win32_DragoWiper_D_2147944726_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/DragoWiper.D!dha"
        threat_id = "2147944726"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "DragoWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {4d 79 41 70 70 6c 69 63 61 74 69 6f 6e 00}  //weight: 2, accuracy: High
        $x_2_2 = "[!] LookupPrivilegeValue failed:" wide //weight: 2
        $x_1_3 = "[!] System disk wiped." wide //weight: 1
        $x_1_4 = "[-] Skipping unsupported file system:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DoS_Win32_DragoWiper_A_2147944819_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/DragoWiper.A!dha"
        threat_id = "2147944819"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "DragoWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4d 79 41 70 70 6c 69 63 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 6d 79 61 70 70 5f 65 78 65 70 61 74 68 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_3 = "Starting network share enumeration..." wide //weight: 1
        $x_1_4 = {00 50 72 6f 63 65 73 73 69 6e 67 20 73 79 73 74 65 6d 20 64 72 69 76 65 3a 20 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 5b 49 4e 46 4f 5d 20 46 69 6c 65 20 64 61 74 61 20 65 6e 63 72 79 70 74 65 64 20 69 6e 20 6d 65 6d 6f 72 79 2e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule DoS_Win32_DragoWiper_B_2147944820_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/DragoWiper.B!dha"
        threat_id = "2147944820"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "DragoWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 4d 79 41 70 70 6c 69 63 61 74 69 6f 6e 00}  //weight: 2, accuracy: High
        $x_2_2 = "[!] OpenProcessToken failed" wide //weight: 2
        $x_1_3 = "[+] Wiping metadata on" wide //weight: 1
        $x_1_4 = "[-] Unable to open volume" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

