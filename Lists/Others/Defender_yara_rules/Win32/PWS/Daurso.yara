rule PWS_Win32_Daurso_A_2147806610_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Daurso.A"
        threat_id = "2147806610"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Daurso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 11 03 c6 30 10 41 3b 4d 14 72 02 33 c9 46 3b 75 0c 72 e5}  //weight: 1, accuracy: High
        $x_1_2 = {80 f9 0a 75 04 4e 48 eb f0 83 c6 fc 56 83 c7 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Daurso_A_2147806861_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Daurso.gen!A"
        threat_id = "2147806861"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Daurso"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 06 02 14 24 32 d3 88 14 06 40 3d 38 4a 00 00 75 ed 5a 5e 5b c3 07 00 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

