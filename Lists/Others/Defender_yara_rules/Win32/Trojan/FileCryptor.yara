rule Trojan_Win32_FileCryptor_BL_2147763697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCryptor.BL!MTB"
        threat_id = "2147763697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 63 72 79 70 74 5c 74 6d 70 5f [0-16] 5c [0-16] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "WriteTapemark" ascii //weight: 1
        $x_10_3 = {6a 65 66 a3 ?? ?? ?? ?? 58 6a 72 66 a3 ?? ?? ?? ?? 58 6a 6e 66 a3 ?? ?? ?? ?? 58 6a 65 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 ?? ?? ?? ?? 58 6a 33 66 a3 ?? ?? ?? ?? 58 6a 32 66 a3 ?? ?? ?? ?? 58 6a 2e 66 a3 ?? ?? ?? ?? 58 6a 64 66 a3 ?? ?? ?? ?? 58 6a 6c}  //weight: 10, accuracy: Low
        $x_10_4 = {30 04 3e 89 75 80 b8 01 00 00 00 83 f0 04 83 6d 80 01 8b 75 80 3b f3 7d e2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FileCryptor_MS_2147771949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileCryptor.MS!MTB"
        threat_id = "2147771949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 33 81 ff ?? ?? ?? ?? 75 08 6a 00 ff 15 ?? ?? ?? ?? 46 3b f7 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 a1 [0-4] 69 [0-5] a3 [0-4] c7 [0-6] 81 [0-6] 8b [0-3] 01 [0-20] 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

