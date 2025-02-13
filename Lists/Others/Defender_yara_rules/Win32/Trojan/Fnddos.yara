rule Trojan_Win32_Fnddos_2147642980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fnddos"
        threat_id = "2147642980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fnddos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wWw.MmDoS.Cn" ascii //weight: 1
        $x_1_2 = "DasDNF111" ascii //weight: 1
        $x_1_3 = "Trojan.Win32.OnlineGames.DasDNF" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

