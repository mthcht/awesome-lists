rule TrojanDropper_Win32_BcryptInject_A_2147817807_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/BcryptInject.A!MTB"
        threat_id = "2147817807"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "BcryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "copy s.dll u.dll>nul" ascii //weight: 1
        $x_1_2 = "type %0 >vir.bat" ascii //weight: 1
        $x_1_3 = "echo %%a>>vir.bat" ascii //weight: 1
        $x_1_4 = "if not exist %%a.com u.dll -bat  vir.bat -save %%a.com -include s.dll -overwrite -nodelete" ascii //weight: 1
        $x_1_5 = "del s.dll /q" ascii //weight: 1
        $x_1_6 = "del vir.bat /q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

