rule Trojan_Win32_Vbalen_SB_2147760434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbalen.SB!MTB"
        threat_id = "2147760434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbalen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F:\\vb\\e.bat" ascii //weight: 1
        $x_1_2 = "male.Attachments.Add (\"c:\\vale.exe\") >nul >>C:\\vale.vbs" ascii //weight: 1
        $x_1_3 = "va\\Valentina.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

