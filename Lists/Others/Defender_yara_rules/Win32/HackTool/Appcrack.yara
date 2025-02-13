rule HackTool_Win32_Appcrack_2147670571_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Appcrack"
        threat_id = "2147670571"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Appcrack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CrackIt_Click" ascii //weight: 1
        $x_1_2 = "winrt_cracking\\" ascii //weight: 1
        $x_1_3 = "BruteDig_Click" ascii //weight: 1
        $x_1_4 = "Dig for .appx URLs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Appcrack_2147670571_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Appcrack"
        threat_id = "2147670571"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Appcrack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[WsServiceCrk] %s" wide //weight: 1
        $x_1_2 = "WSLicensingService-LOBSideloadingActivated" wide //weight: 1
        $x_1_3 = "faking DsRoleGetPrimaryDomainInformation result" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Appcrack_2147670571_2
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Appcrack"
        threat_id = "2147670571"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Appcrack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Windows Store service crack" wide //weight: 1
        $x_1_2 = "WSService crack was successfully installed !" wide //weight: 1
        $x_1_3 = "wsservice_crk.dll" wide //weight: 1
        $x_10_4 = "schtasks /change /disable /TN \"\\Microsoft\\Windows\\WS\\License Validation\"" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

