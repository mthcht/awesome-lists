rule Trojan_Win64_Coinminer_SA_2147731061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.SA"
        threat_id = "2147731061"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\YJ_Project\\Mining_cpp\\Conhost\\x64\\Release\\conhost.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coinminer_A_2147760675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.A!MTB"
        threat_id = "2147760675"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 55 9c 49 bd a8 2a a1 df ad 5d 93 cf 4d 33 ed 4f 8d ?? ?? ?? ?? ?? ?? 66 41 f7 d5 4e 8b ?? ?? ?? ?? ?? ?? 48 c7 44 24 08 ?? ?? ?? ?? ff 74 24 00 9d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coinminer_SBR_2147772781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.SBR!MSR"
        threat_id = "2147772781"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "pool.supportxmr.com" wide //weight: 5
        $x_1_2 = "Haku\\obj\\Debug\\msis.pdb" ascii //weight: 1
        $x_1_3 = "DisableAntiSpyware" wide //weight: 1
        $x_1_4 = "Policies\\Microsoft\\Windows Defender" wide //weight: 1
        $x_1_5 = "currency monero" wide //weight: 1
        $x_1_6 = "start the miner process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Coinminer_RB_2147896802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.RB!MTB"
        threat_id = "2147896802"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 89 c2 41 83 e2 1f 45 32 0c 12 44 88 0c 07 48 ff c0 48 39 c6 74 ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Coinminer_NCA_2147901139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Coinminer.NCA!MTB"
        threat_id = "2147901139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Coinminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 33 c0 41 8d 50 ?? 33 c9 48 8b 03 ff 15 61 17 00 00 e8 68 06 00 00 48 8b d8}  //weight: 5, accuracy: Low
        $x_5_2 = {33 d2 48 8d 0d ?? ?? ?? ?? e8 f6 dc ff ff 8b d8 e8 c3 07 00 00 84 c0 74 50}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

