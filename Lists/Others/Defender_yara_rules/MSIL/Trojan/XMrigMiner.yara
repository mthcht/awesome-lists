rule Trojan_MSIL_XMrigMiner_G_2147747952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XMrigMiner.G!MTB"
        threat_id = "2147747952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XMrigMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 73 00 3a 00 7b 00 69 00 6d 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 4c 00 65 00 76 00 65 00 6c 00 3d 00 69 00 6d 00 70 00 65 00 72 00 73 00 6f 00 6e 00 61 00 74 00 65 00 7d}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 4c 00 69 00 6e 00 65 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 4e 00 61 00 6d 00 65 00 3d 00 27 00 7b 00 30 00 7d}  //weight: 1, accuracy: High
        $x_1_3 = {78 00 6d 00 72 00 2e 00 70 00 6f 00 6f 00 6c 00 2e 00 6d 00 69 00 6e 00 65 00 72 00 67 00 61 00 74 00 65 00 2e 00 63 00 6f 00 6d}  //weight: 1, accuracy: High
        $x_1_4 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 56 00 69 00 64 00 65 00 6f 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 00 1d 56 00 69 00 64 00 65 00 6f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72}  //weight: 1, accuracy: High
        $x_1_5 = "KillLastProc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

