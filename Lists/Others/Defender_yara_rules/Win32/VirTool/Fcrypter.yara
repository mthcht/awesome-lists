rule VirTool_Win32_Fcrypter_A_2147605032_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Fcrypter.gen!A"
        threat_id = "2147605032"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Fcrypter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 90 81 3c 24 68 90 83 c4 28 68 74 02 eb ff 68 80 38 90 90 68 83 c0 07 40 68 90 36 8b 03 54 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Fcrypter_B_2147607453_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Fcrypter.gen!B"
        threat_id = "2147607453"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Fcrypter"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 83 74 0c 03 ?? e2 f9 c3 10 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 54 68 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

