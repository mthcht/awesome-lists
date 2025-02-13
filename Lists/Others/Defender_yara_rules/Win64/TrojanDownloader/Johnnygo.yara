rule TrojanDownloader_Win64_Johnnygo_A_2147825966_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Johnnygo.A!dha"
        threat_id = "2147825966"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Johnnygo"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "expand 32-byte kexpand 32-byte k" ascii //weight: 1
        $x_1_2 = "c:/go/work/serviceII/service.go" ascii //weight: 1
        $x_1_3 = "c:/go/src/github.com/kardianos/service/service.go" ascii //weight: 1
        $x_1_4 = "C:/Users/john/go/src/golang.org/x/sys/windows/svc/service.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

