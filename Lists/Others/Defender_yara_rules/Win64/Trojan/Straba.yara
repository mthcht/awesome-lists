rule Trojan_Win64_Straba_ED_2147833840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Straba.ED!MTB"
        threat_id = "2147833840"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Straba"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\TRRE\\GTRWQE.pdb" ascii //weight: 1
        $x_1_2 = "OutputDebugStringA" ascii //weight: 1
        $x_1_3 = "GetModuleFileNameA" ascii //weight: 1
        $x_1_4 = "GetScrollInfo" ascii //weight: 1
        $x_1_5 = "ExtractIconW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

