rule VirTool_Win32_Williez_A_2147844469_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Williez.A!MTB"
        threat_id = "2147844469"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Williez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/Ne0nd0g" ascii //weight: 1
        $x_1_2 = "github.com/Binject" ascii //weight: 1
        $x_1_3 = "github.com/kensh1ro/willie" ascii //weight: 1
        $x_1_4 = ".localhost/channels" ascii //weight: 1
        $x_1_5 = "InjectionHandler.func2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

