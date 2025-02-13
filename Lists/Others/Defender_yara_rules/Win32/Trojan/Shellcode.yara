rule Trojan_Win32_Shellcode_GPA_2147902460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shellcode.GPA!MTB"
        threat_id = "2147902460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8d 74 26 00 89 c1 83 e1 1f 0f b6 0c 0c 30 0c 02 83 c0 01 39 c3 75 ed}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

