rule Trojan_Win64_ShellRunner_JL_2147838047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellRunner.JL!MTB"
        threat_id = "2147838047"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellRunner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shellcode.dll" ascii //weight: 1
        $x_1_2 = "Failed to load shellcode.dll" ascii //weight: 1
        $x_1_3 = "RunThatShit" ascii //weight: 1
        $x_1_4 = {00 02 00 00 d0 14 00 00 00 10 00 00 00 00 00 40 01 00 00 00 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

