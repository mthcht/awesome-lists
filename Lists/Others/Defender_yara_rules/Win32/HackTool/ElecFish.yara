rule HackTool_Win32_ElecFish_A_2147735689_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ElecFish.A!dha"
        threat_id = "2147735689"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ElecFish"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CCGC_LOG ===> Receive Make Session Frame RemoteSessionID" ascii //weight: 1
        $x_1_2 = "LLGC_LOG ===> Make Session Fail" ascii //weight: 1
        $x_1_3 = "LLGC_LOG ===> Remote Session Disconnected" ascii //weight: 1
        $x_1_4 = "CCGCLOG ===> try connect to %s:%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

