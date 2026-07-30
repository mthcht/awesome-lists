rule HackTool_Win64_Welevate_B_2147974817_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Welevate.B"
        threat_id = "2147974817"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Welevate"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\installservice_lpe_shell" wide //weight: 1
        $x_1_2 = "C:\\ProgramData\\installservice_staticmap_lpe.txt" wide //weight: 1
        $x_1_3 = "VR.InstallService.StaticMapPayload.Instance" wide //weight: 1
        $x_1_4 = "CreateInstallServiceWork" wide //weight: 1
        $x_1_5 = "(GetUserNameW failed)" wide //weight: 1
        $x_1_6 = "cmd.exe /Q" wide //weight: 1
        $x_1_7 = "installservice_lpe_payload.dll" ascii //weight: 1
        $x_1_8 = "installservice_lpe_payload.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

