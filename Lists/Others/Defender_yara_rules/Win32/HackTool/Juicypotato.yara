rule HackTool_Win32_Juicypotato_AMTB_2147947193_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Juicypotato!AMTB"
        threat_id = "2147947193"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Juicypotato"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SweetPotato.exe" ascii //weight: 2
        $x_2_2 = "SweetPotato.pdb" ascii //weight: 2
        $x_2_3 = "printSpoofer" ascii //weight: 2
        $x_2_4 = "PotatoAPI" ascii //weight: 2
        $x_1_5 = "winRMListener" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

