rule Trojan_Win32_MemCCDump_A_2147689106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MemCCDump.A!POS"
        threat_id = "2147689106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MemCCDump"
        severity = "Critical"
        info = "POS: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 61 72 64 4e 75 6d 62 65 72 22 3e 5b 30 2d 39 5d 7b 31 35 2c 31 39 7d 3c 2f 46 69 65 6c 64 3e 29 7c 28 7e 43 43 4d 5b 30 2d 39 5d 7b 31 35 2c 31 39 7d 44 5b 30 2d 39 5d 7b 34 7d 7e 29 29 00}  //weight: 1, accuracy: High
        $x_1_2 = "Found track data at %s with PID " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MemCCDump_A_2147689106_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MemCCDump.A!POS"
        threat_id = "2147689106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MemCCDump"
        severity = "Critical"
        info = "POS: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "125"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "DiabloHorn (Proud Member of: KD-Team)" ascii //weight: 50
        $x_50_2 = "Dumping private memory for pid %s to %s.dmp..." ascii //weight: 50
        $x_10_3 = "Process Memory Dumper" ascii //weight: 10
        $x_10_4 = "Found track data at %s with PID %d!" ascii //weight: 10
        $x_5_5 = {73 73 6c 67 77 2e 65 78 65 00}  //weight: 5, accuracy: High
        $x_5_6 = {76 69 73 61 64 2e 65 78 65 00}  //weight: 5, accuracy: High
        $x_5_7 = {61 64 69 68 74 74 70 73 65 72 76 65 72 73 76 63 2e 65 78 65 00}  //weight: 5, accuracy: High
        $x_5_8 = {69 62 65 72 71 73 2e 65 78 65 00}  //weight: 5, accuracy: High
        $x_5_9 = {65 64 63 73 76 72 2e 65 78 65 00}  //weight: 5, accuracy: High
        $x_5_10 = {63 61 6c 73 72 76 2e 65 78 65 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 5 of ($x_5_*))) or
            ((2 of ($x_50_*) and 1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_50_*) and 2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MemCCDump_A_2147689106_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MemCCDump.A!POS"
        threat_id = "2147689106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MemCCDump"
        severity = "Critical"
        info = "POS: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Found track data at %s with PID %d!" ascii //weight: 1
        $x_1_2 = "Dump1ng p1iv4t3 m3mry" ascii //weight: 1
        $x_1_3 = "((B(([0-9]{13,16})|([0-9]|\\s){13,25})\\^[A-Z\\s0-9]{0,30}\\/[A-Z\\s0-9]" ascii //weight: 1
        $x_1_4 = "|(<Field name=\"CardNumber\">[0-9]{15,19}</Field>))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

