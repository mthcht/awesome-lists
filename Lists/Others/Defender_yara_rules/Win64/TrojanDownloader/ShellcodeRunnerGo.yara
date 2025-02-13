rule TrojanDownloader_Win64_ShellcodeRunnerGo_C_2147926184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ShellcodeRunnerGo.C!MTB"
        threat_id = "2147926184"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellcodeRunnerGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "syscall.RawSockaddrAny" ascii //weight: 1
        $x_1_2 = "pe.RelocEntry" ascii //weight: 1
        $x_1_3 = "encoding/gob/encoder.go" ascii //weight: 1
        $x_1_4 = "github.com/sethgrid/pester" ascii //weight: 1
        $x_1_5 = "text/template/exec.go" ascii //weight: 1
        $x_1_6 = "vendor/golang.org/x/net/http/httpproxy/proxy.go" ascii //weight: 1
        $x_1_7 = "net/http/cookie.go" ascii //weight: 1
        $x_1_8 = "net/url.(*URL).Hostname" ascii //weight: 1
        $x_1_9 = "net/url.(*URL).Port" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

