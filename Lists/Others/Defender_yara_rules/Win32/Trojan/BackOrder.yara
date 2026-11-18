rule Trojan_Win32_BackOrder_2147982328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BackOrder!atmn"
        threat_id = "2147982328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BackOrder"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/c powershell Add-MpPreference -ExclusionPath 'C:\\Users\\public'" ascii //weight: 3
        $x_2_2 = "main.primer1_paso" ascii //weight: 2
        $x_2_3 = "main.proc1esar" ascii //weight: 2
        $x_1_4 = "main.un1_zip" ascii //weight: 1
        $x_1_5 = "C:/windows_update/main.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

