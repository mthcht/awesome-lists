rule Virus_Win32_Frostui_A_2147693897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Frostui.gen!A"
        threat_id = "2147693897"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Frostui"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3d 51 04 0f 85 ?? ?? ?? ?? c1 e8 10 83 e0 0f 66 3d 01 00 0f 8e}  //weight: 1, accuracy: Low
        $x_1_2 = {ae 75 fd c6 07 00 83 ef 05 c7 07 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {3d 2e 64 6f 63 0f 85 ?? ?? ?? ?? 6a 02 50 ff 75 08 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {e9 04 00 00 00 2a 2e 2a 00 68}  //weight: 1, accuracy: High
        $x_1_5 = "net localgroup administrators Guest /add" ascii //weight: 1
        $x_1_6 = "net share C$=C: /grant:everyone,full" ascii //weight: 1
        $x_1_7 = {34 30 53 31 31 38 54 32 30 31 33 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

