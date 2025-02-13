rule Ransom_Win32_InfoDot_PA_2147758863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/InfoDot.PA!MTB"
        threat_id = "2147758863"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "InfoDot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 08 8b 16 8b ?? b9 33 fa 23 fb 33 d7 89 16 8b 54 24 ?? 8b 08 31 ?? 91 42 89 54 24 ?? 3b 54 24 ?? 7c}  //weight: 1, accuracy: Low
        $x_5_2 = ".info@mymail9[dot]com" wide //weight: 5
        $x_1_3 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del \"%s" wide //weight: 1
        $x_1_4 = "taskkill /IM sql* /f" ascii //weight: 1
        $x_1_5 = {5c 65 6e 63 5c [0-16] 5c 65 6e 63 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

