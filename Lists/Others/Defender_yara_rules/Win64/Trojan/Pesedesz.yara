rule Trojan_Win64_Pesedesz_MK_2147967846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Pesedesz.MK!MTB"
        threat_id = "2147967846"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Pesedesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {89 f0 31 d2 41 f7 f0 80 ca 30 42 88 54 0c 40 49 ff c1 89 c6}  //weight: 20, accuracy: High
        $x_15_2 = {8a 01 42 88 44 04 30 49 ff c0 48 ff c9}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

