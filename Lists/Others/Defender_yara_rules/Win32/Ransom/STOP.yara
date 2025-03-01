rule Ransom_Win32_STOP_BS_2147743901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/STOP.BS!MTB"
        threat_id = "2147743901"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "STOP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e:\\doc\\my work (c++)\\_git\\encryption\\encryptionwinapi\\Salsa20.inl" wide //weight: 1
        $x_1_2 = "ns1.kriston.ug" ascii //weight: 1
        $x_1_3 = "ns2.chalekin.ug" ascii //weight: 1
        $x_1_4 = "ns3.unalelath.ug" ascii //weight: 1
        $x_1_5 = "ns4.andromath.ug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_STOP_RP_2147907738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/STOP.RP!MTB"
        threat_id = "2147907738"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "STOP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d c3 01 00 00 75 06 8d 91 31 a2 00 00 81 fa 41 01 00 00 75 0c 89 ?? ?? ?? ?? 00 89 ?? ?? ?? ?? 00 40 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

