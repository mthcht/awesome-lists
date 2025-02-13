rule Trojan_Win64_ShellcodeRunnerGo_A_2147922805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellcodeRunnerGo.A!MTB"
        threat_id = "2147922805"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunnerGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "net/http.(*Client).Get" ascii //weight: 1
        $x_1_2 = "encoding/base64.init" ascii //weight: 1
        $x_1_3 = "crypto/subtle.xorBytes" ascii //weight: 1
        $x_1_4 = "build/loader/temp/temp.go" ascii //weight: 1
        $x_1_5 = "net/http/socks_bundle.go" ascii //weight: 1
        $x_1_6 = "encoding/hex/hex.go" ascii //weight: 1
        $x_1_7 = {41 0f b6 44 24 17 89 c1 83 e0 1f 48 89 c3 48 0f ba e8 07 ?? 48 8b b4 24 d8 01 00 00 f6 c1 20 48 0f 44 d8 eb 07 31 db 45 31 e4 31 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

