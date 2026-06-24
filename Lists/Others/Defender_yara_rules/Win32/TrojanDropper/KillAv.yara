rule TrojanDropper_Win32_KillAv_PA_2147972197_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/KillAv.PA!MTB"
        threat_id = "2147972197"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "KillAv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 16 66 0f 61 ca 66 0f 38 1d c1 66 0f 6f c3 66 0f 6f c8 66 0f 6d fb [0-96] 66 0f 38 1d e0 66 0f 6c c2 30 04 0f 66 0f fd cc 66 0f 6f d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

