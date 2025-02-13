rule Worm_Win32_BATRun_DA_2147888101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/BATRun.DA!MTB"
        threat_id = "2147888101"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "BATRun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /create /tn folder /tr d:\\folder.exe /sc minute /mo 1 /f" ascii //weight: 1
        $x_1_2 = "attrib -h -s d:\\autorun.inf" ascii //weight: 1
        $x_1_3 = "copy d:\\folder.exe c:\\" ascii //weight: 1
        $x_1_4 = "for /r \\ %%a in (folder.exe) do copy \"d:\\folder.exe\" %%a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

