rule Trojan_Win64_XMRMiner_PAA_2147777163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XMRMiner.PAA!MTB"
        threat_id = "2147777163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XMRMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 57 69 6e 52 69 6e 67 [0-4] 2e 73 79 73}  //weight: 1, accuracy: Low
        $x_1_2 = "xmrig-notls.exe" ascii //weight: 1
        $x_1_3 = "\\SqlTools.exe" ascii //weight: 1
        $x_1_4 = "procexp64.exe" ascii //weight: 1
        $x_1_5 = "procexp.exe" ascii //weight: 1
        $x_1_6 = "sokers.exe" ascii //weight: 1
        $x_1_7 = "xmrig.exe" ascii //weight: 1
        $x_1_8 = "nssm.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

