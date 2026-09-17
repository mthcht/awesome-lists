rule Trojan_Win32_Atorea_G_2147978361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Atorea.G!MTB"
        threat_id = "2147978361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Atorea"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 58 f1 f6 fe ab dd de 62 67 6b b0 9b 1a ed e6 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Atorea_G_2147978361_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Atorea.G!MTB"
        threat_id = "2147978361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Atorea"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ea e8 35 d6 ff ff 83 78 30 ?? 7e 08 e8 2a d6 ff ff ff 48 30 48 83 c4 30 5d c3 cc cc cc cc cc 40 55 48 83 ec 20 48 8b ea 48 8b 01 33 c9 81 38 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

