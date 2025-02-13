rule Worm_Win32_Cyrmsmb_A_2147743982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cyrmsmb.A!MSR"
        threat_id = "2147743982"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cyrmsmb"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\CymulateWorm1\\Release\\CymulateSMBWorm.pdb" ascii //weight: 1
        $x_1_2 = "Spreaded:true %ls" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

