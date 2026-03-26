rule TrojanDropper_Win64_RustyStealer_CX_2147965714_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/RustyStealer.CX!MTB"
        threat_id = "2147965714"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\app_shell.rs" ascii //weight: 5
        $x_5_2 = "\\halo_gate.rs" ascii //weight: 5
        $x_5_3 = "\\vcruntime140.dll" ascii //weight: 5
        $x_5_4 = "user32.dllshell32.dll" ascii //weight: 5
        $x_5_5 = "cmd.exe ping -n 3 127.0.0.1 >nul & del" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

