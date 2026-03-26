rule Trojan_Win32_SusPyExec_IK_2147965626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPyExec.IK!MTB"
        threat_id = "2147965626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPyExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\Zhujikdo" wide //weight: 1
        $x_1_2 = "Lib\\Image.png" wide //weight: 1
        $x_1_3 = "pythonw.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

