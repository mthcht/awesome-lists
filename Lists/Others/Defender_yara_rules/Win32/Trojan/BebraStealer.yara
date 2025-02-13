rule Trojan_Win32_BebraStealer_GTC_2147836087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BebraStealer.GTC!MTB"
        threat_id = "2147836087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BebraStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 0c 8b 45 08 01 f2 8d 0c b0 31 c0 89 d3 8a 14 83 30 14 01 40 83 f8 ?? 75 f4 46 83 fe ?? 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

