rule HackTool_Win32_CiscoGetPass_2147711706_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CiscoGetPass"
        threat_id = "2147711706"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CiscoGetPass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetPass!  v" ascii //weight: 2
        $x_2_2 = "#Enter the Cisco Encrypted Password:" ascii //weight: 2
        $x_1_3 = "The decrypted password is" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

