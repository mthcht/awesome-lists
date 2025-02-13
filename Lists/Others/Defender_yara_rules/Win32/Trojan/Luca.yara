rule Trojan_Win32_Luca_ALU_2147911550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Luca.ALU!MTB"
        threat_id = "2147911550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Luca"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 e2 0f af de 01 d3 ba cd cc cc cc 0f af fa 01 df 41 ba 33 33 33 33 39 c2 19 fa 89 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Luca_MKV_2147912619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Luca.MKV!MTB"
        threat_id = "2147912619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Luca"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 8b c7 8d 76 04 c1 ea 04 83 c7 04 8b ca c1 e1 04 03 ca 2b c1 8b 4c 24 ?? 03 c5 0f b6 44 04 27 32 44 31 fc 88 46 ff 81 ff 00 28 0c 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

