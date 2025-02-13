rule VirTool_Win64_Shampire_F_2147836059_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Shampire.F!MTB"
        threat_id = "2147836059"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Shampire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Empire" ascii //weight: 1
        $x_1_2 = "CSharpPy" ascii //weight: 1
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_4 = "IronPython.Hosting" ascii //weight: 1
        $x_1_5 = "IronPython.SQLite" ascii //weight: 1
        $x_1_6 = "Agent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

