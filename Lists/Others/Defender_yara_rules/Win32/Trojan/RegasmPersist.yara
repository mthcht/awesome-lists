rule Trojan_Win32_RegasmPersist_Z_2147968720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegasmPersist.Z!MTB"
        threat_id = "2147968720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegasmPersist"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "Start-Process" wide //weight: 1
        $x_1_3 = "\\regasm.exe" wide //weight: 1
        $x_1_4 = "schtasks /create" wide //weight: 1
        $x_1_5 = "/ru SYSTEM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

