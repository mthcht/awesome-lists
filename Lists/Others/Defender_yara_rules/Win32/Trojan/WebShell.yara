rule Trojan_Win32_WebShell_Y_2147828695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WebShell.Y"
        threat_id = "2147828695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WebShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Page_Load" ascii //weight: 1
        $x_1_2 = "POSTFileUpload" ascii //weight: 1
        $x_1_3 = "POSTFileDownload" ascii //weight: 1
        $x_1_4 = "POSTFileDelete" ascii //weight: 1
        $x_1_5 = "POSTCmdExecute" ascii //weight: 1
        $x_1_6 = "/contact.aspx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

