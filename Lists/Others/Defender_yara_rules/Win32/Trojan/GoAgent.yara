rule Trojan_Win32_GoAgent_B_2147916769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GoAgent.B!MTB"
        threat_id = "2147916769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GoAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "User-Agent: %s" ascii //weight: 1
        $x_1_2 = "crypto/subtle/xor.go" ascii //weight: 1
        $x_1_3 = "syscall/syscall.go" ascii //weight: 1
        $x_1_4 = "encoding/base64/base64.go" ascii //weight: 1
        $x_1_5 = ".HollowProcess" ascii //weight: 1
        $x_1_6 = ".WriteProcessMemory" ascii //weight: 1
        $x_1_7 = ".GetRemotePebAddr" ascii //weight: 1
        $x_1_8 = ".RedirectToPayload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

