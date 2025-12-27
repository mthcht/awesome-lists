rule Trojan_Win32_Lauri_ALI_2147958409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lauri.ALI!MTB"
        threat_id = "2147958409"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lauri"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LauriC\\kol.pas" ascii //weight: 2
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_3_3 = "file0a0.dat" ascii //weight: 3
        $x_4_4 = "temp0a1.exe" ascii //weight: 4
        $x_5_5 = "VIRUS: VIR\\Lauri.III" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

