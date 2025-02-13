rule Trojan_Win32_Dapterup_A_2147684349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapterup.A!A"
        threat_id = "2147684349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapterup"
        severity = "Critical"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 64 65 6c 2e 62 61 74 00}  //weight: 2, accuracy: High
        $x_1_2 = {31 08 3b 15 24 12 2b 05 37 03 37}  //weight: 1, accuracy: High
        $x_1_3 = {5e 03 1e 67 9b 0c bb 56 66 6b 6d 64 4e c8 80 06 f1 fc}  //weight: 1, accuracy: High
        $x_2_4 = {8a 54 01 ff 30 14 01 49 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dapterup_A_2147684350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapterup.A!B"
        threat_id = "2147684350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapterup"
        severity = "Critical"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 64 65 6c 2e 62 61 74 00}  //weight: 2, accuracy: High
        $x_1_2 = {31 08 3b 15 24 12 2b 05 37 03 37}  //weight: 1, accuracy: High
        $x_1_3 = {5e 03 1e 67 9b 0c bb 56 66 6b 6d 64 4e c8 80 06 f1 fc}  //weight: 1, accuracy: High
        $x_2_4 = {8a 4c 30 ff 30 0c 30 83 e8 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dapterup_A_2147684351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapterup.A!C"
        threat_id = "2147684351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapterup"
        severity = "Critical"
        info = "C: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 64 65 6c 2e 62 61 74 00}  //weight: 2, accuracy: High
        $x_1_2 = {31 08 3b 15 24 12 2b 05 37 03 37}  //weight: 1, accuracy: High
        $x_1_3 = {5e 03 1e 67 9b 0c bb 56 66 6b 6d 64 4e c8 80 06 f1 fc}  //weight: 1, accuracy: High
        $x_2_4 = {8a 54 08 ff 30 14 08 48 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dapterup_A_2147686915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dapterup.A!D"
        threat_id = "2147686915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dapterup"
        severity = "Critical"
        info = "D: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IE::InstallCert():" ascii //weight: 1
        $x_2_2 = {25 64 2f 25 64 2f 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 00 5b 25 73 5d 3a 5b 25 73 5d 3a 5b 25 69 5d 3a 5b 25 73 5d 3a 5b 25 73 5d 3a 5b 25 69 5d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

