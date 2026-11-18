rule Trojan_Win64_Shellcoderunner_DA_2147921033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shellcoderunner.DA!MTB"
        threat_id = "2147921033"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shellcoderunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8d ac 24 00 02 00 00 48 8d 15 ?? ?? ?? ?? 52 48 8d 15 ?? ?? ?? ?? 52 c3 07 00 48 81 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8d ac 24 00 02 00 00 48 8d 05 ?? ?? ?? ?? 50 55 48 89 e5 48 81 ec 07 00 48 81 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Shellcoderunner_PGR_2147945224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shellcoderunner.PGR!MTB"
        threat_id = "2147945224"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shellcoderunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 fc 48 8b 45 10 48 01 d0 0f b6 00 0f be c0 8d 50 ec 89 d0 c1 f8 ?? c1 e8 ?? 01 c2 0f b6 d2 29 c2 89 d1 8b 55 fc 48 8b 45 10 48 01 d0 89 ca 88 10 83 45 fc ?? 8b 45 fc 3b 45 18 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shellcoderunner_MCV_2147982378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shellcoderunner.MCV!MTB"
        threat_id = "2147982378"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shellcoderunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 48 81 ec f0 00 00 00 48 8b 05 af 62 01 00 48 33 c4 48 89 84 24 e0 00 00 00 8b da 48 8b f1 33 d2 48 8d 4c 24 20}  //weight: 1, accuracy: High
        $x_1_2 = {6f 6f 6b 2d 66 69 6c 74 65 72 36 34 2e 64 6c 6c 00 53 65 74 48 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

