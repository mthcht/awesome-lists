rule HackTool_MSIL_DriveSharp_A_2147832392_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/DriveSharp.A!dha"
        threat_id = "2147832392"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DriveSharp"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "client_id" wide //weight: 1
        $x_1_2 = "client_password" wide //weight: 1
        $x_1_3 = "namespace MsOneDriveRestApi" wide //weight: 1
        $x_1_4 = "LoginGetAccessTokenAndRefreshToken" wide //weight: 1
        $x_1_5 = "CreateDrive.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

