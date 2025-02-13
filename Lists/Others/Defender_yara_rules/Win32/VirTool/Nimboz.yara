rule VirTool_Win32_Nimboz_A_2147835313_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Nimboz.A!MTB"
        threat_id = "2147835313"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Nimboz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 1c 26 40 be 63 00 00 00 41 be 0a 00 00 00 48 8d 4e 9d 48 81 fe c6 00 00 00 ?? ?? 48 83 c3 03 ?? ?? 48 8d 46 a6 48 83 f8 12}  //weight: 1, accuracy: Low
        $x_1_2 = "winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\securitycenter2" ascii //weight: 1
        $x_1_3 = "reg.exe save hklm\\sam" ascii //weight: 1
        $x_1_4 = "cmd /c sdclt.exe" ascii //weight: 1
        $x_1_5 = "cmd /c fodhelper.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

