rule TrojanDropper_Win32_Convagent_GMC_2147904766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Convagent.GMC!MTB"
        threat_id = "2147904766"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {3a e9 3b de 27 0c 04 b8 ee 8b 32 d3 10 cd fd 31 07 ad 6a 33 19 58 0a}  //weight: 5, accuracy: High
        $x_5_2 = {4b 31 42 f1 24 5c 4b 29 ec 2b 02 03 2d c6 f2 a8 5c 6c 0a c5 56 29 d1}  //weight: 5, accuracy: High
        $x_1_3 = "TJprojMain.exe" ascii //weight: 1
        $x_1_4 = "GProc0INkExiTt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

