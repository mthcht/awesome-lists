rule Ransom_Win64_Anubis_C_2147943929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Anubis.C!MTB"
        threat_id = "2147943929"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Anubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 3b 66 10 76 33 48 83 ec 28 48 89 6c 24 20 48 8d 6c 24 20 48 8d 05 94 4e 07 00 bb 12 00 00 00 31 c9 31 ff e8 ?? ?? ?? ?? 48 85 db 0f 94 c0 48 8b 6c 24 20}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 89 d8 48 8d 1d 12 0d 07 00 b9 05 00 00 00 e8 ?? ?? ?? ?? 48 8b 4c 24 38 48 8b 54 24 28 4c 8b 44 24 58 4c 8b 4c 24 48 4c 8b 54 24 30 4c 8b 5c 24 50 89 c3 48 8b 44 24 40 84 db 74}  //weight: 2, accuracy: Low
        $x_1_3 = ".anubis" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Anubis_A_2147944333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Anubis.A"
        threat_id = "2147944333"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Anubis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".anubis" ascii //weight: 1
        $x_1_2 = "RESTORE FILES.txt" ascii //weight: 1
        $x_1_3 = "/KEY=" ascii //weight: 1
        $x_1_4 = "/WIPEMODE" ascii //weight: 1
        $x_1_5 = "/elevated" ascii //weight: 1
        $x_1_6 = "/PFAD=" ascii //weight: 1
        $x_1_7 = "Deleting services..." ascii //weight: 1
        $x_1_8 = "Encryption completed in:" ascii //weight: 1
        $x_1_9 = "Directory walk completed with warnings: %v" ascii //weight: 1
        $x_1_10 = "=== Encryption Statistics ===" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

