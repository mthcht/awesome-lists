rule Trojan_Win64_PirateStealer_BSA_2147932086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PirateStealer.BSA!MTB"
        threat_id = "2147932086"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PirateStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {0f a2 89 c6 83 f8 00 74 33 81 fb 47 65 6e 75 75 1e 81 fa 69 6e 65 49 75 16 81 f9 6e 74 65 6c 75 0e c6 05 7d 9a 6e 00 01 c6 05 79 9a 6e 00 01}  //weight: 6, accuracy: High
        $x_6_2 = "PirateStealerBTWapplication" ascii //weight: 6
        $x_2_3 = "Lk8Jw3LoMGluSMFK8Ytm" ascii //weight: 2
        $x_2_4 = "A3A4CNCcCfCoCsLlLmLoLtLuMcMeMnNdNlNoOKONOUPcPdPePfPiPoPsSTScSkSmSoTeToV1V2V3V5V6YiZlZpZs" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PirateStealer_ABC_2147942238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PirateStealer.ABC!MTB"
        threat_id = "2147942238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PirateStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 89 58 10 ba e8 0f 00 00 48 89 c3 48 8b 43 08 48 89 d9 48 01 c1 48 29 f2 48 89 13 48 01 f0 48 89 43 08 31 d2 49 89 f0 48 83 c4 20 5b 5f 5e e9}  //weight: 4, accuracy: High
        $x_1_2 = {ba 00 10 00 00 31 c9 41 b8 00 30 00 00 41 b9 04 00 00 00 ff 15 ?? ?? ?? 00 48 85 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

