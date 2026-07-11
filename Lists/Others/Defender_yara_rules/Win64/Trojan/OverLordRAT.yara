rule Trojan_Win64_OverLordRAT_SX_2147973378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OverLordRAT.SX!MTB"
        threat_id = "2147973378"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OverLordRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "main.KeylogFileMessage" ascii //weight: 30
        $x_20_2 = "main.ShellResultMessage" ascii //weight: 20
        $x_10_3 = "main.FileDownloadMessage" ascii //weight: 10
        $x_10_4 = "main.ProcessKillMessage" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

