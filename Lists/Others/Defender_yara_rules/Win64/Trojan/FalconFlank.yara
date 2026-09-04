rule Trojan_Win64_FalconFlank_DA_2147977566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FalconFlank.DA!MTB"
        threat_id = "2147977566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FalconFlank"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\??\\pipe\\FALCONFLANK" ascii //weight: 10
        $x_1_2 = "\\FALCONF0" ascii //weight: 1
        $x_1_3 = "\\??\\C:\\TEMP\\Flanker_{C4E8D0E1-988D-42b7-BEA7-6BF9589BB111}" ascii //weight: 1
        $x_1_4 = "PROJECT.THISDOCUMENT.AUTOOPEN" ascii //weight: 1
        $x_1_5 = "_VBA_PROJECT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

