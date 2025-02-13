rule Worm_Win32_Spetcrum_2147599860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Spetcrum"
        threat_id = "2147599860"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Spetcrum"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "poSendMail_SendFailed" ascii //weight: 1
        $x_1_2 = "SystemTimeToTzSpecificLocalTime" ascii //weight: 1
        $x_1_3 = "SMTPHostValidation" ascii //weight: 1
        $x_1_4 = "SSL seguro (128 bits)" ascii //weight: 1
        $x_1_5 = "picLock10" ascii //weight: 1
        $x_1_6 = "C:\\Arquivos de programas" ascii //weight: 1
        $x_1_7 = "AERO BIZ COM COOP" wide //weight: 1
        $x_1_8 = "Account MSN:" wide //weight: 1
        $x_1_9 = "RemoteHost" wide //weight: 1
        $x_1_10 = "_=_NextPart_000_" wide //weight: 1
        $x_1_11 = "{a-agudo}" wide //weight: 1
        $x_1_12 = "HTMLMAIL1_ADDRMAIL" wide //weight: 1
        $x_1_13 = "Windows Millenium" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

