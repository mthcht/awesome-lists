rule Ransom_Win32_Weenloc_A_2147689401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Weenloc.A"
        threat_id = "2147689401"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Weenloc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6a 00 6a 01 e8 ?? ?? ?? ?? 8b f0 85 f6 74 27 6a 00 56 e8 ?? ?? ?? ?? 83 f8 01 1b db 43 56 e8 ?? ?? ?? ?? eb 11}  //weight: 3, accuracy: Low
        $x_1_2 = {00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 74 61 73 6b 6d 67 72 2e 65 78 65 00 55 8b}  //weight: 1, accuracy: Low
        $x_1_3 = "System\\CurrentControlSet\\Control\\SafeBoot\\" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

