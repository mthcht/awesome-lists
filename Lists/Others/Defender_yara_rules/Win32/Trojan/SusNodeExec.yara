rule Trojan_Win32_SusNodeExec_ABB_2147961722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusNodeExec.ABB!MTB"
        threat_id = "2147961722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusNodeExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "/C start" wide //weight: 1
        $x_1_3 = "/min" wide //weight: 1
        $x_1_4 = "\\AppData\\Local\\Programs\\ManualReaderPro\\node\\node.exe" wide //weight: 1
        $x_1_5 = ".js" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

