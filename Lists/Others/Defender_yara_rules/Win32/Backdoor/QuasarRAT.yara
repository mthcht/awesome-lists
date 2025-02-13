rule Backdoor_Win32_QuasarRAT_A_2147731545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/QuasarRAT.A"
        threat_id = "2147731545"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "QuasarRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xClient.Core." ascii //weight: 1
        $x_1_2 = "GetKeyloggerLogs" ascii //weight: 1
        $x_1_3 = "DoProcessKill" ascii //weight: 1
        $x_1_4 = "DoVisitWebsite" ascii //weight: 1
        $x_1_5 = "DoUploadAndExecute" ascii //weight: 1
        $x_1_6 = "DoWebcamStop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

