rule Trojan_Win32_Vbdowninst_SA_2147743309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbdowninst.SA!MSR"
        threat_id = "2147743309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbdowninst"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":\\ProgramData\\ipras.vbs" ascii //weight: 1
        $x_1_2 = "iplogger.org/" ascii //weight: 1
        $x_1_3 = {5c 49 6e 69 73 74 61 6c 6c [0-2] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

