rule TrojanDropper_Win32_Azorult_EB_2147835662_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Azorult.EB!MTB"
        threat_id = "2147835662"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUSearcher 1.3.2.85" ascii //weight: 1
        $x_1_2 = "{2b16a38E-91B4-4910-9006-18fb2576934b}" ascii //weight: 1
        $x_1_3 = "{sysuserinfoname}" ascii //weight: 1
        $x_1_4 = "{sysuserinfoorg}" ascii //weight: 1
        $x_1_5 = "Administrationsverkty" wide //weight: 1
        $x_1_6 = "ShellExecuteExA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

