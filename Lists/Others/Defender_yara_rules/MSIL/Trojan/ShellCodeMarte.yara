rule Trojan_MSIL_ShellCodeMarte_MS_2147981561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ShellCodeMarte.MS!MTB"
        threat_id = "2147981561"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShellCodeMarte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Local\\Semaphore:Default" ascii //weight: 1
        $x_1_2 = "PAYLOAD:" ascii //weight: 1
        $x_1_3 = "template_x86_windows_mixed_mode.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

