rule Trojan_Win32_Jaku_A_2147711552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaku.A!dha"
        threat_id = "2147711552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaku"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 5c 42 6f 74 5c 47 6c 6f 62 61 6c 2e 63 70 70 00 5b 25 73 3a 25 30 33 64 5d 20 53 65 74 20 46 61 6b 65 20 49 45 20 41 67 65 6e 74 20 54 61 67}  //weight: 1, accuracy: High
        $x_1_2 = "index.php|uid|v|pi|if|" ascii //weight: 1
        $x_1_3 = "|WindowsUpdate|systeminfo;net use;net user;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Jaku_B_2147711553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaku.B!dha"
        threat_id = "2147711553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaku"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 6f 6d 70 53 76 63 2e 65 78 65 00 00 00 00 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 53 65 72 76 69 63 65 73 5c 53 76 63 53 74 61 72 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {52 32 44 32 25 73 00 00 00 6b 65 72 6e 65 6c 33 32 00 00 00 00 25 73 20 52 32 44 33 25 73 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 6e 65 72 5f 53 74 61 74 75 73 00 00 00 00 25 64 00 00 25 73 25 73 2e 64 6c 6c 00 00 00 00 25 73 25 73 2e 74 6e 70 00 00 00 00 53 74 61 72 74 65 72 00 69 6e 6e 65 72 5f 45 73 63 6c 00 00 69 6e 6e 65 72 5f 55 6e 69 71 49 44 00}  //weight: 1, accuracy: High
        $x_1_4 = {25 73 5c 25 73 2e 69 66 6f 00 00 00 25 73 2e 69 66 6f 00 00 25 73 5c 25 73 00 00 00 25 73 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Jaku_C_2147711554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaku.C!dha"
        threat_id = "2147711554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaku"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 00 25 54 4d 50 25 5c 57 4c 49 45 53 56 43 2e 45 58 45 00 26}  //weight: 1, accuracy: High
        $x_1_2 = {2f 75 70 64 61 74 65 2e 70 68 70 00 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 53 48 45 4c 4c 33 32}  //weight: 1, accuracy: High
        $x_1_3 = {4c 61 4c 62 61 79 00 00 25 4d 25 57 49 53 43 45 45 00 00 00 98 42 88 42 78 42 68 42 5c 42 54 42}  //weight: 1, accuracy: High
        $x_1_4 = {25 00 73 00 5c 00 2a 00 2e 00 2a 00 00 00 00 00 5c 00 00 00 25 00 73 00 25 00 73 00 00 00 00 00 25 00 73 00 3a 00 5c 00 2a 00 2e 00 2a 00 00 00 25 00 63 00 3a 00 5c 00 00 00 00 00 5c 00 5c 00 3f 00 5c 00 25 00 63 00 3a 00 00 00 25 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 46 00 69 00 6c 00 65 00 73 00 25 00 5c 00 33 00 36 00 30 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Jaku_F_2147711599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jaku.F!dha"
        threat_id = "2147711599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jaku"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 73 65 6c 66 2e 62 61 74 00 69 6d 20 77 75 61 75 63 6c 74 2e 65 78 65 0d 0a 0d 0a 64 65 6c 20 2f 66 20 2f 71 20 22 25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 53 74 61 72 74 75 70 5c 77 75 61 75 63 6c 74 2e 65 78 65 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

