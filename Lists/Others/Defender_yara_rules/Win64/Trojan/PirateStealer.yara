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

