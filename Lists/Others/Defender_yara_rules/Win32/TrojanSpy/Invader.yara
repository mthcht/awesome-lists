rule TrojanSpy_Win32_Invader_S_2147744793_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Invader.S!MSR"
        threat_id = "2147744793"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Invader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "coding\\project\\main\\result\\result.pdb" ascii //weight: 1
        $x_1_2 = "ntoskrnl.pdb" ascii //weight: 1
        $x_1_3 = "E.LOVDNS" ascii //weight: 1
        $x_1_4 = "c start" wide //weight: 1
        $x_1_5 = "CreateClientSecurity" ascii //weight: 1
        $x_1_6 = "DeleteAccess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

