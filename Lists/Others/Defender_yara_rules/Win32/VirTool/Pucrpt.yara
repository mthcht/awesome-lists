rule VirTool_Win32_Pucrpt_A_2147794468_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Pucrpt.A!MTB"
        threat_id = "2147794468"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Pucrpt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 0e 10 40 00 [0-85] fc [0-5] ac [0-5] 30 d0 [0-5] aa [0-5] c1 ca 05 [0-5] 6b d2 07 [0-5] f7 c3 01 00 00 00 [0-21] 83 c6 [0-5] d1 cb [0-5] 49 [0-5] 85 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {50 68 00 10 40 00 6a 00 6a 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

