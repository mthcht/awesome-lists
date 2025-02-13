rule TrojanDownloader_Win32_Wolfic_D_2147835299_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wolfic.D"
        threat_id = "2147835299"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wolfic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "56762eb9-411c-4842-9530-9922c46ba2d" wide //weight: 2
        $x_2_2 = "HijackingLib.dll" ascii //weight: 2
        $x_1_3 = "\\WSOCK32.dll.EnumProtocol" ascii //weight: 1
        $x_1_4 = "\\WSOCK32.dll.GetAcceptExSockaddrs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Wolfic_E_2147835300_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wolfic.E"
        threat_id = "2147835300"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wolfic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "27E57D84-4310-4825-AB22-743C78B8F3AA " wide //weight: 2
        $x_2_2 = "HijackingLib.dll" ascii //weight: 2
        $x_1_3 = "\\duser.dll.IsStartDelete" ascii //weight: 1
        $x_1_4 = "\\duser.dll.InvalidateGadget" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

