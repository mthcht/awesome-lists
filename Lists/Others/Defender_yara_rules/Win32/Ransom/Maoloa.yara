rule Ransom_Win32_Maoloa_KA_2147741806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Maoloa.KA"
        threat_id = "2147741806"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Maoloa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOW TO BACK YOUR FILES" wide //weight: 1
        $x_1_2 = "vssadmin Delete Shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_4 = "DisableRealtimeMonitoring" wide //weight: 1
        $x_1_5 = "DisableAntiSpyware" wide //weight: 1
        $x_1_6 = "C:\\ids.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

