rule Trojan_Win32_Flyagent_AN_2147818105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flyagent.AN!MTB"
        threat_id = "2147818105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flyagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "SetProxyCredentials" ascii //weight: 2
        $x_2_2 = "Microsoft\\3389.bat" ascii //weight: 2
        $x_2_3 = "net stop termservice  /y" ascii //weight: 2
        $x_2_4 = "takeown /F c:\\windows\\system32\\termsrv.dll /A" ascii //weight: 2
        $x_2_5 = "{NumLock}" ascii //weight: 2
        $x_2_6 = "taskkill /im cmd.exe" ascii //weight: 2
        $x_2_7 = "MTI0LjIyMi4zNC4yNDZ8ODI4Mg==" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

