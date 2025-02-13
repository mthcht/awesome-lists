rule Trojan_Win32_Plite_A_2147905985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plite.A!MTB"
        threat_id = "2147905985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 14 0c 66 85 d7 8d ad ?? ?? ?? ?? f8 80 d1 ?? 8b 4c 25 ?? f5 f8 3b e3 33 cb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

