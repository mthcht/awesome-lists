rule TrojanDownloader_Win32_AgentRazy_SN_2147804297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AgentRazy.SN!MTB"
        threat_id = "2147804297"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentRazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mastergamenameper.club" ascii //weight: 10
        $x_1_2 = "browser.exe" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Machiner" wide //weight: 1
        $x_1_4 = "k_tag" wide //weight: 1
        $x_1_5 = "3_tag" wide //weight: 1
        $x_1_6 = "/C ping 127.0.0.1 /n 300" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

