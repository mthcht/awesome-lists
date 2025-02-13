rule Trojan_Win64_ShellCodeLoadz_A_2147927945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShellCodeLoadz.A!MTB"
        threat_id = "2147927945"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShellCodeLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 6c 24 30 48 83 ca 07 48 8b 69 18 48 89 7c 24 28 4c 89 64 24 20 45 33 e4 48 3b d3 77 40 48 8b cd 48 8b c3 48 d1 e9 48 2b c1 48 3b e8}  //weight: 1, accuracy: High
        $x_1_2 = "Shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

