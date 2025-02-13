rule Trojan_Win32_Sergen_A_2147740020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sergen.A"
        threat_id = "2147740020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sergen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sysreg.exe" wide //weight: 1
        $x_1_2 = "ik.PowerShell.PS2EXEHostRawUI.SetBufferContents" wide //weight: 1
        $x_1_3 = "PS2EXE_Host" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

