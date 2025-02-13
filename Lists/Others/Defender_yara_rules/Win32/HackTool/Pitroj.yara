rule HackTool_Win32_Pitroj_A_2147719214_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Pitroj.A"
        threat_id = "2147719214"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Pitroj"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HackSpy Trojan Exploit.pyt" ascii //weight: 1
        $x_1_2 = "step 1->click on build trojan button" ascii //weight: 1
        $x_1_3 = "This tool was build by Prabhat Awasthi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

