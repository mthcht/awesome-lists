rule Trojan_Win32_RegAsmInject_Z_2147980383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RegAsmInject.Z!MTB"
        threat_id = "2147980383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RegAsmInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "\\RegAsm.exe" wide //weight: 1
        $x_1_3 = ".Invoke($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

