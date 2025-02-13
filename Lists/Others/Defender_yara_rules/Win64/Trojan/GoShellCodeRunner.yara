rule Trojan_Win64_GoShellCodeRunner_A_2147920332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoShellCodeRunner.A!MTB"
        threat_id = "2147920332"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoShellCodeRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 4c 24 28 48 89 48 08 48 c7 40 10 00 30 00 00 48 c7 40 18 40 00 00 00 ?? ?? ?? ?? ?? ?? ?? 48 89 c3 bf 04 00 00 00 48 89 d0 48 89 f9}  //weight: 1, accuracy: Low
        $x_1_2 = "Go build ID:" ascii //weight: 1
        $x_1_3 = "encoding/hex.DecodeString" ascii //weight: 1
        $x_1_4 = "encoding/base64.(*Encoding).Decode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

