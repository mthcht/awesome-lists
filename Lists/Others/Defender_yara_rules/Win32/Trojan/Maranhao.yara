rule Trojan_Win32_Maranhao_GAQ_2147952369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maranhao.GAQ!MTB"
        threat_id = "2147952369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maranhao"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 02 ?? ?? ?? 02 00 b8 3a 00 ?? ?? ?? ?? ?? ?? 46 02 00 0a}  //weight: 8, accuracy: Low
        $x_8_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 02 ?? ?? ?? 02 00 b8 3a 00 ?? ?? ?? ?? ?? ?? 43 02 00 0a}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Maranhao_GAT_2147952414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Maranhao.GAT!MTB"
        threat_id = "2147952414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Maranhao"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 01 ?? ?? ?? 01 00 b8 3a 00 ?? ?? ?? ?? ?? ?? ec 01 00 0a}  //weight: 8, accuracy: Low
        $x_8_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 02 ?? ?? ?? 01 00 b8 3a 00 ?? ?? ?? ?? ?? ?? fb 01 00 0a}  //weight: 8, accuracy: Low
        $x_8_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 02 ?? ?? ?? 02 00 92 3a 00 ?? ?? ?? ?? ?? ?? 33 02 00 e4}  //weight: 8, accuracy: Low
        $x_8_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 02 ?? ?? ?? 02 00 92 3a 00 ?? ?? ?? ?? ?? ?? 28 02 00 e4}  //weight: 8, accuracy: Low
        $x_8_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 01 ?? ?? ?? 01 00 92 3a 00 ?? ?? ?? ?? ?? ?? d2 01 00 e4}  //weight: 8, accuracy: Low
        $x_8_6 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 02 ?? ?? ?? 02 00 92 3a 00 ?? ?? ?? ?? ?? ?? 20 02 00 e4}  //weight: 8, accuracy: Low
        $x_8_7 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 02 ?? ?? ?? 02 00 92 3a 00 ?? ?? ?? ?? ?? ?? 1e 02 00 e4}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

