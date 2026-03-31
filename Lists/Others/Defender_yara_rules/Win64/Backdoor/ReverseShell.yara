rule Backdoor_Win64_ReverseShell_MK_2147965936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ReverseShell.MK!MTB"
        threat_id = "2147965936"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ReverseShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_35_1 = {48 b8 63 6d 64 2e 65 78 65 00 ba 00 00 00 00 48 89 45 d0 48 89 55 d8 48 8d 55 e0 b8 00 00 00 00 b9 1d 00 00 00 48 89 d7 f3 48 ab 48 89 fa 89 02 48 83 c2 04 66 89 02 48 83 c2 02 88 02 48 83 c2 01}  //weight: 35, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

