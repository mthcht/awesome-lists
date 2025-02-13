rule Trojan_Win32_BmsDllInject_A_2147753226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BmsDllInject.A!MTB"
        threat_id = "2147753226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BmsDllInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Release\\x64\\RunResExe.pdb" ascii //weight: 1
        $x_1_2 = "powershell.exe -NoP -NonI -W Hidden -ep Bypass -enc cwBjAGgAdABhAHMAawBzACAALwBjAHIAZQBhAHQAZQAgAC8AcgB1ACAA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

