rule Trojan_Win64_Oyster_AA_2147908622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.AA!MTB"
        threat_id = "2147908622"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 d0 8b 85 ?? ?? ?? ?? 48 89 54 c5 ?? 83 85 ?? ?? ?? ?? 01 81 bd ?? ?? ?? ?? ?? ?? 00 00 76 ?? 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {48 63 d0 8b 85 ?? ?? ?? ?? 48 89 54 c5 ?? 83 85 ?? ?? ?? ?? 01 81 bd ?? ?? ?? ?? ?? ?? 00 00 0f 86 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Oyster_A_2147913092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oyster.A"
        threat_id = "2147913092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oyster"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 58 45 00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 54 65 73 74 00 43 4f 4d 00 6f 70 65 6e 00 74 65 6d 70 00 25 73 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

