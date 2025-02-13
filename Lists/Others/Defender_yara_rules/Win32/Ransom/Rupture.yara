rule Ransom_Win32_Rupture_PAA_2147811013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Rupture.PAA!MTB"
        threat_id = "2147811013"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Rupture"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Monero/XMR" ascii //weight: 1
        $x_1_2 = "DisableAntiVirus" wide //weight: 1
        $x_1_3 = "\\Desktop\\Read-Me.txt" ascii //weight: 1
        $x_1_4 = "taskkill /f /im taskmgr.exe" ascii //weight: 1
        $x_1_5 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

