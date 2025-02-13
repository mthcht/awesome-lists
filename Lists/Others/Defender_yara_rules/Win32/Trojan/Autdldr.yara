rule Trojan_Win32_Autdldr_GG_2147753779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Autdldr.GG!MTB"
        threat_id = "2147753779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Autdldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RUNWAIT ( \"cmd /c start /b powershell -noexit -exec bypass -window" ascii //weight: 1
        $x_1_2 = "Downloadstring('http" ascii //weight: 1
        $x_1_3 = "[AppDomain]::CurrentDomain.Load([Convert]::Frombase64String(-join $string[-1..-$string.Length]));" ascii //weight: 1
        $x_1_4 = "$methodInfo.Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

