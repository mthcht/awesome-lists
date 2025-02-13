rule Trojan_Win64_Implant_A_2147890065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Implant.A!MTB"
        threat_id = "2147890065"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Implant"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b 44 24 ?? 48 8d 44 24 ?? 48 8b 4c 24 ?? 45 33 c9 ba 10 66 00 00 48 89 44 24}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b 4c 24 ?? 48 8d 84 24 ?? ?? ?? ?? 48 89 44 24 ?? 45 33 c9 48 8b 84 24 ?? ?? ?? ?? 45 33 c0 33 d2 48 89 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Implant_B_2147892636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Implant.B!MTB"
        threat_id = "2147892636"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Implant"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "calc_payload addr" ascii //weight: 2
        $x_2_2 = "%-20s : 0x%-016p" ascii //weight: 2
        $x_2_3 = "exec_mem addr" ascii //weight: 2
        $x_2_4 = "Hit me 1st!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Implant_C_2147896554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Implant.C!MTB"
        threat_id = "2147896554"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Implant"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 45 d7 43 72 65 61 c7 45 db 74 65 46 69 c7 45 df 6c 65 4d 61 c7 45 e3 70 70 69 6e 66 c7 45 e7 67 41}  //weight: 2, accuracy: High
        $x_2_2 = {c7 45 a7 4d 61 70 56 c7 45 ab 69 65 77 4f c7 45 af 66 46 69 6c 66 c7 45 b3 65}  //weight: 2, accuracy: High
        $x_2_3 = {c7 45 c7 55 6e 6d 61 c7 45 cb 70 56 69 65 c7 45 cf 77 4f 66 46 c7 45 d3 69 6c 65}  //weight: 2, accuracy: High
        $x_2_4 = {c7 45 b7 56 69 72 74 c7 45 bb 75 61 6c 50 c7 45 bf 72 6f 74 65 66 c7 45 c3 63 74}  //weight: 2, accuracy: High
        $x_2_5 = {c7 45 ef 77 69 6e 64 c7 45 f3 6f 77 73 2e c7 45 f7 73 74 6f 72 c7 45 fb 61 67 65 2e c7 45 ff 64 6c 6c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

