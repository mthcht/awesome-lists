rule Misleading_Win32_SystemBooster_239472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/SystemBooster"
        threat_id = "239472"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBooster"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PhSuppNum" ascii //weight: 1
        $x_1_2 = "www.omnitweak.com/" wide //weight: 1
        $x_1_3 = "Software\\SystemBooster" wide //weight: 1
        $x_1_4 = "&redir=/[PRODSMNAME]/purchase/[SYSVEN]/ref_[AFF]/track_[TRNAME]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

