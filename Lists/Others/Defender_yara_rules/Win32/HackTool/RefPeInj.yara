rule HackTool_Win32_RefPeInj_A_2147729983_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/RefPeInj.A!!RefPeInj.gen!A"
        threat_id = "2147729983"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "RefPeInj"
        severity = "High"
        info = "RefPeInj: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReflectivePE" wide //weight: 1
        $x_1_2 = "ReflectiveExe" wide //weight: 1
        $x_2_3 = "$RemoteScriptBlock -ArgumentList @($PEBytes" wide //weight: 2
        $x_3_4 = "@(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)" wide //weight: 3
        $x_1_5 = "$LoadLibrarySC" wide //weight: 1
        $x_1_6 = "$GetProcAddressSC" wide //weight: 1
        $x_1_7 = "$CallDllMainSC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

