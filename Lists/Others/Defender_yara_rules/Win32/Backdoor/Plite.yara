rule Backdoor_Win32_Plite_SE_2147834942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Plite.SE!MTB"
        threat_id = "2147834942"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Plite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 06 8b c8 c1 f9 05 8b 0c 8d a0 57 42 00 83 e0 1f c1 e0 06 8d 44 01 24 8a 08 32 4d fe 80 e1 7f 30 08 8b 06 8b c8 c1 f9 05}  //weight: 2, accuracy: High
        $x_1_2 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 72 6d 64 69 72 20 22 25 73 22 0d 0a 64 65 6c 20 22 25 73}  //weight: 1, accuracy: High
        $x_1_3 = "HanAgent_pe.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

