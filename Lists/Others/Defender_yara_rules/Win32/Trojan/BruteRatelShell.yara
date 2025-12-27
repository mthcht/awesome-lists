rule Trojan_Win32_BruteRatelShell_AA_2147956262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BruteRatelShell.AA!MTB"
        threat_id = "2147956262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BruteRatelShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e1 00 48 ff c8 88 02 48 31 fa 48 8d 5b 01 48 39 f3 75 ?? 48 29 f3 48 01 da 48 31 fa ff e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

