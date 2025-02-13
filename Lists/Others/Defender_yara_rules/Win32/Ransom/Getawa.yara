rule Ransom_Win32_Getawa_A_2147773480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Getawa.A!MTB"
        threat_id = "2147773480"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Getawa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "md %windir%\\SysWOW64\\java\\jawa" ascii //weight: 1
        $x_1_2 = {70 69 6e 67 20 2d 6e 20 31 20 [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 20 7c 20 66 69 6e 64 20 22 54 54 4c 3d 22 20 3e 6e 75 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "getrartime.bat" ascii //weight: 1
        $x_1_4 = "getrartime.exe" ascii //weight: 1
        $x_1_5 = "copy wr-3.-71.zip wr-3.-71.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Getawa_B_2147773481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Getawa.B!MTB"
        threat_id = "2147773481"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Getawa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "del /q /s /f system@interrupts.exe" ascii //weight: 1
        $x_1_2 = "md %windir%\\SysWOW64\\java\\jawa" ascii //weight: 1
        $x_1_3 = "del %windir%\\system32\\superdatvpn.exe" ascii //weight: 1
        $x_1_4 = "%temp%\\rarcek.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

