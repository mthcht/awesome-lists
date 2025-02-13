rule Trojan_Win32_BMoonVMProt_SA_2147753174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BMoonVMProt.SA!MSR"
        threat_id = "2147753174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BMoonVMProt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FUckTentct" ascii //weight: 1
        $x_1_2 = "gg.ini" ascii //weight: 1
        $x_1_3 = "dnf.exe" ascii //weight: 1
        $x_1_4 = "Bg.cmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

