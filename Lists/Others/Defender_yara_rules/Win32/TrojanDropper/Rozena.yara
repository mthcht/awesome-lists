rule TrojanDropper_Win32_Rozena_ARA_2147911690_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rozena.ARA!MTB"
        threat_id = "2147911690"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 ca c1 e2 0d 31 ca 89 d6 c1 ee 11 31 d6 89 f1 c1 e1 05 31 f1 89 8c 05 50 ff ff ff 83 c0 04 83 f8 3c 72 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

