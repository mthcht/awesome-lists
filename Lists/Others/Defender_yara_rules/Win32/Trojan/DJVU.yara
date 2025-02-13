rule Trojan_Win32_DJVU_GN_2147893838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DJVU.GN!MTB"
        threat_id = "2147893838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DJVU"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d0 8b c8 c1 ea 05 03 54 24 2c c1 e1 04 03 4c 24 24 03 c3 33 d1 33 d0 2b fa 8b cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DJVU_IP_2147894695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DJVU.IP!MTB"
        threat_id = "2147894695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DJVU"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cb c1 e1 04 03 4c 24 34 8b c3 c1 e8 05 03 44 24 2c 8d 14 2b 33 ca 89 44 24 18 89 4c 24 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

