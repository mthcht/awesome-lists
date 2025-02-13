rule Trojan_Win32_Minxer_A_2147688840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minxer.A"
        threat_id = "2147688840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minxer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 65 78 65 20 2d 61 20 [0-64] 3a}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 65 78 65 20 2d 70 6f 6f 6c 69 70 3d [0-16] 20 2d 70 6f 6f 6c 70 6f 72 74 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {00 6d 73 75 70 64 61 74 65 37 31 5c}  //weight: 1, accuracy: High
        $x_1_4 = {00 69 73 77 69 7a 61 72 64 [0-4] 5c}  //weight: 1, accuracy: Low
        $x_2_5 = {00 69 6e 64 65 78 65 72 2e 65 78 65}  //weight: 2, accuracy: High
        $x_3_6 = "cidaemon.exe -c proxy.conf" ascii //weight: 3
        $x_1_7 = {2e 64 6c 6c 00 73 74 61 72 74 6d 65 00 73 74 6f 70 00}  //weight: 1, accuracy: High
        $x_1_8 = {2e 64 6c 6c 00 72 75 6e 6d 65 00 73 74 6f 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Minxer_A_2147688840_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minxer.A"
        threat_id = "2147688840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minxer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".exe -a m7 -o stratum+tcp://xcnpool2.1gh.com:7333 -u CdVrxhAT8KLCtWAsmG4MqU2sP6JMNz9kwZ -p x --retries" ascii //weight: 1
        $x_1_2 = "change the number of threads (-t x) that the miner should use" ascii //weight: 1
        $x_1_3 = "XCN.1GH.COM - Cryptonite Mining Pool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Minxer_A_2147690099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Minxer.gen!A"
        threat_id = "2147690099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Minxer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 73 75 70 64 61 74 65 2e 37 7a 00 [0-9] 70 72 6f 78 79 2e 63 6f 6e 66}  //weight: 1, accuracy: Low
        $x_1_2 = {00 6d 73 75 70 64 61 74 65 37 31 5c 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 64 6c 6c 00 61 73 64 61 73 64 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

