rule SoftwareBundler_Win32_Pokavampo_222268_0
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Pokavampo"
        threat_id = "222268"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Pokavampo"
        severity = "8"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 57 69 6e 43 68 65 63 6b 53 65 74 75 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 6d 69 49 6e 73 70 65 63 74 6f 72 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = "&pr=vo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule SoftwareBundler_Win32_Pokavampo_222268_1
{
    meta:
        author = "defender2yara"
        detection_name = "SoftwareBundler:Win32/Pokavampo"
        threat_id = "222268"
        type = "SoftwareBundler"
        platform = "Win32: Windows 32-bit platform"
        family = "Pokavampo"
        severity = "8"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\wincheck" ascii //weight: 1
        $x_1_2 = "?AUThank_you@Define_the_symbol__ATL_MIXED@@" ascii //weight: 1
        $x_1_3 = "?AVIExplorerUIAutomation@@" ascii //weight: 1
        $x_1_4 = "context.download-ap.com:5555/mta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

