rule Backdoor_Win32_Cobalt_RPY_2147833389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cobalt.RPY!MTB"
        threat_id = "2147833389"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cobalt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 c1 89 ca 8b 45 dc 8d 48 02 8b 45 d4 01 c8 88 10 83 45 dc 03 83 45 e0 04 8b 45 d8 83 e8 02 39 45 e0 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

