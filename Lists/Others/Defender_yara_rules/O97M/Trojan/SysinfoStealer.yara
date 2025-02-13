rule Trojan_O97M_SysinfoStealer_A_2147747985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/SysinfoStealer.A!MSR"
        threat_id = "2147747985"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SysinfoStealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinHttpReq.Send" ascii //weight: 1
        $x_1_2 = "winMgmts.ExecQuery(Base64DecodeString" ascii //weight: 1
        $x_2_3 = "Base64EncodeString(GetDocName & \"|\" & GetComputerInfo & \"|\" & GetOSInfo & \"|\" & GetAV & \"|\" & GetProc)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

