rule HackTool_Win32_Proratz_A_2147925719_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Proratz.A!MTB"
        threat_id = "2147925719"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Proratz"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ProRat" ascii //weight: 1
        $x_1_2 = "Cyan Dusk" ascii //weight: 1
        $x_1_3 = "System.Net.URLClient.TCredentialsStorage.TCredential" ascii //weight: 1
        $x_1_4 = "System.Net.URLClient" ascii //weight: 1
        $x_1_5 = "ServerSocket6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

