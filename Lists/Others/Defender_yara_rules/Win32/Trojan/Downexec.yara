rule Trojan_Win32_Downexec_A_2147627716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Downexec.A"
        threat_id = "2147627716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Downexec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 ff 01 00 00 85 c0 76 15 6a 00 8b 45 ?? 50 e8 ?? ?? ?? ff c1 e8 09 40 c1 e0 09 89 43 ?? c7 43 ?? e0 00 00 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

