rule HackTool_Win32_LogMeIn_DA_2147957180_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/LogMeIn.DA!MTB"
        threat_id = "2147957180"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "LogMeIn"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "GoToResolveUnattendedUpdater.exe" ascii //weight: 20
        $x_1_2 = "GoToResolveLoggerProcess.exe" ascii //weight: 1
        $x_1_3 = "GoToResolveUnattendedUpdater.pdb" ascii //weight: 1
        $x_1_4 = "forceKillServiceProcesses" ascii //weight: 1
        $x_1_5 = "logmein_remotecontrol.exe.cmd" ascii //weight: 1
        $x_1_6 = "dumpster.dev01-console.gotoresolve.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

