rule Trojan_Win32_NetWired_DSK_2147753271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWired.DSK!MTB"
        threat_id = "2147753271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWired"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a d1 80 f2 04 88 14 01 41 81 f9 00 e1 f5 05 72}  //weight: 1, accuracy: High
        $x_1_2 = "iqA2vbXFZuUFjDH2C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NetWired_RC_2147794524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetWired.RC!MTB"
        threat_id = "2147794524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetWired"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E:\\cplusplus" ascii //weight: 1
        $x_1_2 = "Release\\Adobe" ascii //weight: 1
        $x_1_3 = {6a 04 68 00 10 00 00 6a 04 6a 00 ff}  //weight: 1, accuracy: High
        $x_1_4 = {6a 40 68 00 30 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "ReadProcessMemory" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

