rule Trojan_Win64_PenTera_EH_2147826938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PenTera.EH!MTB"
        threat_id = "2147826938"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PenTera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RemoteRunnerAPC" ascii //weight: 1
        $x_1_2 = "CryptAcqH" ascii //weight: 1
        $x_1_3 = "uireContH" ascii //weight: 1
        $x_1_4 = "/c ping -n 20 127.0.0.1 > nul & del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PenTera_AB_2147843949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PenTera.AB!MTB"
        threat_id = "2147843949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PenTera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 0f b6 5c 24 ?? 44 0f b6 54 24 ?? 48 83 c7 03 44 89 dd 44 89 d6 41 c1 fa 02 c1 fd 04 41 c1 e3 04 41 83 e2 0f 41 89 ec 0f b6 6c 24 ?? 45 01 da c1 e6 06 41 83 e4 03 40 02 74 24 ?? 44 88 57 ?? 45 31 db 41 8d 2c ac 40 88 77 ?? 40 88 6f ?? 4c 39 cb 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PenTera_LK_2147844209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PenTera.LK!MTB"
        threat_id = "2147844209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PenTera"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "10SelfDelBat" ascii //weight: 1
        $x_1_2 = "11BasePayload" ascii //weight: 1
        $x_1_3 = "16ShellcodePayload" ascii //weight: 1
        $x_1_4 = "RemoteRunner" ascii //weight: 1
        $x_1_5 = "9PEPayload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

