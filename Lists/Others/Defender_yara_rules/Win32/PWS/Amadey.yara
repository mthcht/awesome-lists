rule PWS_Win32_Amadey_GG_2147774352_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Amadey.GG!MTB"
        threat_id = "2147774352"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 95 ec fe ff ff 8b 95 ec fe ff ff 0f b6 84 15 f8 fe ff ff 8b 8d f0 fe ff ff 0f b6 94 0d f8 fe ff ff 33 d0 89 95 d8 fd ff ff 8b 85 f0 fe ff ff 8a 8d d8 fd ff ff 88 8c 05 f8 fe ff ff 0f b6 95 d8 fd ff ff 8b 85 ec fe ff ff 0f b6 8c 05 f8 fe ff ff 33 ca 89 8d d4 fd ff ff 8b 95 ec fe ff ff 8a 85 d4 fd ff ff 88 84 15 f8 fe ff ff 0f b6 8d d4 fd ff ff 8b 95 f0 fe ff ff 0f b6 84 15 f8 fe ff ff 33 c1 8b 8d f0 fe ff ff 88 84 0d f8 fe ff ff e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Amadey_GG_2147774352_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Amadey.GG!MTB"
        threat_id = "2147774352"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "User-Agent: Uploador" ascii //weight: 10
        $x_1_2 = "scr=up" ascii //weight: 1
        $x_1_3 = "x%.2x%.2x%.2x%.2x%.2x%.2x" ascii //weight: 1
        $x_1_4 = "name=\"data\"" ascii //weight: 1
        $x_1_5 = "Content-Disposition: form-data" ascii //weight: 1
        $x_1_6 = "Content-Type: application/octet-stream" ascii //weight: 1
        $x_1_7 = "Content-Type: multipart/form-data" ascii //weight: 1
        $x_1_8 = "Connection: Keep-Alive" ascii //weight: 1
        $x_1_9 = "Content-Length:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Amadey_GG_2147774352_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Amadey.GG!MTB"
        threat_id = "2147774352"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Outlook" ascii //weight: 1
        $x_1_2 = "IMAP Password" ascii //weight: 1
        $x_1_3 = "POP3 Password" ascii //weight: 1
        $x_1_4 = "<password>" ascii //weight: 1
        $x_1_5 = "<Pass encoding=\"base64\">" ascii //weight: 1
        $x_1_6 = "Pidgin" ascii //weight: 1
        $x_1_7 = "\\FileZilla\\sitemanager.xml" ascii //weight: 1
        $x_1_8 = "\\.purple\\accounts.xml" ascii //weight: 1
        $x_1_9 = "\\Wcx_ftp.ini" ascii //weight: 1
        $x_1_10 = "\\winscp.ini" ascii //weight: 1
        $x_1_11 = "RealVNC" ascii //weight: 1
        $x_1_12 = "TightVNC" ascii //weight: 1
        $x_1_13 = "Password=" ascii //weight: 1
        $x_1_14 = "Content-Length:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

