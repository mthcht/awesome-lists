rule Trojan_Win32_Penguish_GTB_2147938912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Penguish.GTB!MTB"
        threat_id = "2147938912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Penguish"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 51 51 83 c4 04 81 c9 ?? ?? ?? ?? 59 51 51 83 c4 04 81 c9 ?? ?? ?? ?? 59 56 81 ee ?? ?? ?? ?? 81 f6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

