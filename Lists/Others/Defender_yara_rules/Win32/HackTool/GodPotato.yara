rule HackTool_Win32_GodPotato_AMTB_2147958495_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/GodPotato!AMTB"
        threat_id = "2147958495"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "GodPotato"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\user\\source\\repos\\GodPotato2\\GodPotato2\\obj\\x64\\Release\\net8.0-windows8.0\\win-x64\\Vicrea.pdb" ascii //weight: 1
        $x_1_2 = "Vicrea.dll" ascii //weight: 1
        $x_1_3 = "Did not roll forward because apply_patches=%d, version_compatibility_range=%s chose [%s]" ascii //weight: 1
        $x_1_4 = "MThmNzA3NzAtOGU2NC0xMWNmLTlhZjEtMDAyMGFmNmU3MmY0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

