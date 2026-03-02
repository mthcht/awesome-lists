rule TrojanDownloader_Win32_AgentTesla_CCHW_2147905171_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AgentTesla.CCHW!MTB"
        threat_id = "2147905171"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 1a 8a 1c 31 32 d3 8b 5d ?? 88 14 01 b8 01 00 00 00 03 c7 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_AgentTesla_C_2147963931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AgentTesla.C!MTB"
        threat_id = "2147963931"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 20 00 79 00 6f 00 75 00 72 00 61 00 64 00 6f 00 72 00 61 00 62 00 6c 00 65}  //weight: 2, accuracy: High
        $x_2_2 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 64 00 6f 00 6e 00 27 00 74 00 20 00 67 00 75 00 65 00 73 00 20 00 74 00 68 00 65 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 21}  //weight: 2, accuracy: High
        $x_2_3 = "frmLogin" ascii //weight: 2
        $x_2_4 = "frmUserInfo" ascii //weight: 2
        $x_2_5 = "txtUsername" ascii //weight: 2
        $x_2_6 = "txtPassword" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

