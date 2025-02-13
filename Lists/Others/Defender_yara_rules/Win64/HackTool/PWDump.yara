rule HackTool_Win64_PWDump_M_2147744665_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PWDump.M!MSR"
        threat_id = "2147744665"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PWDump"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pwsrv.exe" ascii //weight: 1
        $x_1_2 = "starting dll injection" ascii //weight: 1
        $x_1_3 = "createremotethread ok" ascii //weight: 1
        $x_1_4 = "servpw64.exe" ascii //weight: 1
        $x_1_5 = "lsaext.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

