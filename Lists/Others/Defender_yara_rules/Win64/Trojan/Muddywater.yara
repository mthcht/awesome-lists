rule Trojan_Win64_Muddywater_GVA_2147959129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Muddywater.GVA!MTB"
        threat_id = "2147959129"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Muddywater"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "194.11.246.101:443" ascii //weight: 5
        $x_1_2 = "SOFTWARE\\Microsoft\\Cryptography" ascii //weight: 1
        $x_1_3 = "main.runRemoteProxyRelay" ascii //weight: 1
        $x_1_4 = "main.GenerateCA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

