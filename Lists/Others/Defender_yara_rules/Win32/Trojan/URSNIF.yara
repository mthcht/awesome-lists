rule Trojan_Win32_URSNIF_QW_2147806302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/URSNIF.QW!MTB"
        threat_id = "2147806302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "URSNIF"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 09 8b 44 24 04 f7 e1 c2 10 00 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2 10 00}  //weight: 10, accuracy: High
        $x_3_2 = "killsuggest" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

