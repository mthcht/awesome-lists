rule Trojan_Win32_AdamantiumTheif_EH_2147846272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AdamantiumTheif.EH!MTB"
        threat_id = "2147846272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AdamantiumTheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b c8 8b c2 c1 e8 02 c1 e1 03 8b 04 86 d3 e8 88 04 1a 42 83 fa 14 72 e0}  //weight: 5, accuracy: High
        $x_1_2 = "FreeVBucks.html" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

