rule Trojan_Win32_Cipduk_A_2147730654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cipduk.A!dha"
        threat_id = "2147730654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cipduk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 77 6e 55 72 6c 46 69 6c 65 00 44 6f 77 6e 52 75 6e 55 72 6c 46 69 6c 65 00 00 52 75 6e 55 72 6c 42 69 6e 49 6e 4d 65 6d 00 00 55 6e 49 6e 73 74 61 6c 6c 00 00 00 75 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 00 6f 00 6d 00 6d 00 6f 00 6e 00 2f 00 75 00 70 00 2f 00 75 00 70 00 5f 00 62 00 61 00 73 00 65 00 2e 00 70 00 68 00 70 00 20 00 [0-16] 20 00 47 00 61 00 67 00 65 00 6e 00 61 00 31 00 20 00 77 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6f 6d 6d 6f 6e 2f 75 70 2f 75 70 5f 62 61 73 65 2e 70 68 70 20 [0-16] 20 47 61 67 65 6e 61 31 20 77 69 72 65 73 68 61 72 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cipduk_A_2147730654_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cipduk.A!dha"
        threat_id = "2147730654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cipduk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 6f 77 6e 55 72 6c 46 69 6c 65 00 44 6f 77 6e 52 75 6e 55 72 6c 46 69 6c 65 00 00 52 75 6e 55 72 6c 42 69 6e 49 6e 4d 65 6d 00 00 55 6e 49 6e 73 74 61 6c 6c 00 00 00 75 6d 28 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 00 6f 00 6d 00 6d 00 6f 00 6e 00 2f 00 75 00 70 00 2f 00 75 00 70 00 5f 00 62 00 61 00 73 00 65 00 2e 00 70 00 68 00 70 00 20 00 [0-16] 20 00 47 00 61 00 67 00 65 00 6e 00 61 00 31 00 20 00 77 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {63 6f 6d 6d 6f 6e 2f 75 70 2f 75 70 5f 62 61 73 65 2e 70 68 70 20 [0-16] 20 47 61 67 65 6e 61 31 20 77 69 72 65 73 68 61 72 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cipduk_E_2147734126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cipduk.E"
        threat_id = "2147734126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cipduk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "System32\\version.muiem32\\wcnapi.mui" ascii //weight: 1
        $x_1_2 = "com/board/sitemahttp://checkin.travelsanignacio.com/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cipduk_F_2147734450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cipduk.F!dha"
        threat_id = "2147734450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cipduk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 3a 5c 50 42 5c 56 53 41 67 65 6e 74 5c [0-2] 5c 73 5c 43 6c 69 65 6e 74 5c 53 6f 75 72 63 65 5c 43 6c 69 65 6e 74 53 6f 75 72 63 65 5c 52 65 6c 65 61 73 65 5c 50 42 43 6f 6e 66 69 67 2e 70 64 62}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

