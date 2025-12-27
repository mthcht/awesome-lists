rule HackTool_Win64_PrintSpoofer_MX_2147957242_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PrintSpoofer.MX!MTB"
        threat_id = "2147957242"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PrintSpoofer"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "pipe\\%ws\\pipe\\spoolss" wide //weight: 5
        $x_5_2 = "SeImpersonatePrivilege" wide //weight: 5
        $x_1_3 = "WinSta0\\Default" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

