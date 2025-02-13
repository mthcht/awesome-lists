rule Trojan_Win32_dorifel_RDA_2147845698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/dorifel.RDA!MTB"
        threat_id = "2147845698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "dorifel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0e 84 c9 74 ?? 6a 01 83 e9 41 58 d3 e0 56 33 f8 ff 15 ?? ?? ?? ?? 8d 74 06 01 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

