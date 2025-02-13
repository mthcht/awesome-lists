rule Trojan_Win32_Kadena_D_2147695438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kadena.gen!D"
        threat_id = "2147695438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kadena"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {37 48 45 76 ?? 74 47 73 74 ?? 72 72 6f 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

