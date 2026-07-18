rule Trojan_Win64_ValleyRatz_Z_2147973548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRatz.Z!MTB"
        threat_id = "2147973548"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 39 f7 76 32 41 8b 0c b6 49 89 f4 48 ff c6 48 01 d9 e8 ?? ?? ?? ?? 44 39 e8 75 e4 4b 8d 14 24 44 8b 65 bc 48 01 fa 0f b7 04 13 49 8d 04 84 8b 04 03 48 01 d8 eb 02 31 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRatz_ZC_2147973549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRatz.ZC!MTB"
        threat_id = "2147973549"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer" ascii //weight: 1
        $x_1_2 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = "AmsiScanBuffer" ascii //weight: 1
        $x_1_4 = "%X.tmp" ascii //weight: 1
        $x_1_5 = "\\Temp\\" ascii //weight: 1
        $x_1_6 = "ExecuteShellcodeGlobal: Returned" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRatz_ZC_2147973549_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRatz.ZC!MTB"
        threat_id = "2147973549"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRatz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[STABLE] Dedicated Thread Active. Jump to Payload: %p (Header: %02X %02X %02X %02X)" ascii //weight: 1
        $x_1_2 = "[ADAPT] Spawning Dedicated Execution Thread" ascii //weight: 1
        $x_1_3 = "[STABLE] ExecuteShellcodeGlobal: Returned" ascii //weight: 1
        $x_1_4 = "[SYSTEM] VEH Handler Registered" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

