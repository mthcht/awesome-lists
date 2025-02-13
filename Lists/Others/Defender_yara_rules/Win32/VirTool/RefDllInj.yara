rule VirTool_Win32_RefDllInj_A_2147706530_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/RefDllInj.A!!RefDllInj.gen!A"
        threat_id = "2147706530"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefDllInj"
        severity = "Critical"
        info = "RefDllInj: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 5a e8 00 00 00 00 5b 52 45 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 89 c3 57 6a 04 50 ff d0 68 ?? ?? ?? ?? 6a 05 50 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

