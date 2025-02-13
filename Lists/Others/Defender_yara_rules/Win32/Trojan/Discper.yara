rule Trojan_Win32_Discper_A_2147688648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Discper.A"
        threat_id = "2147688648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Discper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "-u 454HDLDtqCLS" ascii //weight: 2
        $x_1_2 = "-a cryptonight -o stratum+tcp://" ascii //weight: 1
        $x_1_3 = {6e 65 74 2e 65 78 65 00 61 63 63 6f 75 6e 74 73 20 2f 6d 61 78 70 77 61 67 65 3a 75 6e 6c 69 6d 69 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 66 20 2f 69 6d 20 63 6d 64 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Discper_A_2147689260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Discper.gen!A"
        threat_id = "2147689260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Discper"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 37 37 37 37 00 [0-5] 7b 22 6d 65 74 68 6f 64 22 3a 20 22 67 65 74 77 6f 72 6b 22 2c 20 22 70 61 72 61 6d 73 22 3a 20 5b 5d 2c 20 22 69 64 22 3a 30}  //weight: 1, accuracy: Low
        $x_1_2 = "454HDLDtqCLS24EsDAYorf9QAVkNqQPdJTaEBrdi9pVELUH6ZSU37VqV8UAoTYV7k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Discper_E_2147691923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Discper.E"
        threat_id = "2147691923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Discper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 9d 8d 45 f0 50 3e ff 15 ?? ?? ?? ?? 9c 58 05 ?? ?? ?? ?? 2d ?? 02 00 00 ff d0 c9 c3 00}  //weight: 1, accuracy: Low
        $x_1_2 = {57 68 d0 07 00 00 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 33 f6 56 56 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 3d b7 00 00 00 75 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

