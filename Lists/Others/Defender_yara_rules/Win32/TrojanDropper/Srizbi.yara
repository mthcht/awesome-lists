rule TrojanDropper_Win32_Srizbi_B_2147598718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Srizbi.gen!B"
        threat_id = "2147598718"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Srizbi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 64 00 00 69 6e 73 74 61 6c 6c 65 72 20 6f 6b 32 00 00 00 67 75 74 21 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6f 6b 00 00 66 61 69 6c 65 64 20 74 6f 20 66 69 6e 64 20 6d 61 72 6b 65 72 00 00 00 65 72 72 6f 72 00 00 00 32 00 00 00 6f 6b 00 00 66 61 69 6c 65 64 20 74 6f 20 66 69 6e 64 20 6d 61 72 6b 65 72 00 00 00 65 72 72 6f 72 00 00 00 61 64 64 72 20 3d 20 25 78 2c 20 66 69 6c 65 73 69 7a 65 20 3d 20 25 64 2c 20 53 54 41 52 54 31 20 3d 20 25 78 2c 20 6d 61 72 6b 65 72 31 5f 73 69 7a 65 20 3d 20 25 64}  //weight: 2, accuracy: Low
        $x_2_2 = "FlushInstructionCache" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Srizbi_C_2147605120_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Srizbi.gen!C"
        threat_id = "2147605120"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Srizbi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 0f be 11 (83 f2 ??|81 f2 ?? 00) 88 55 ef 8b 45 f4 83 c0 01 89 45 f4 8b 4d f0 8a 55 ef 88 11 8b 45 f0 83 c0 01 89 45 f0 8b 4d e8 83 c1 01 89 4d e8 0f be 55 ef 85 d2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Srizbi_E_2147610679_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Srizbi.gen!E"
        threat_id = "2147610679"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Srizbi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f0 0f be 11 8b 45 f4 0f be 88 ?? ?? ?? ?? 33 d1 88 55 eb 8b 55 f0 83 c2 01 89 55 f0 8b 45 f4 83 c0 01 25 07 00 00 80 79 05 48 83 c8 f8 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

