rule Trojan_Win64_CountLoader_SNA_2147965235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CountLoader.SNA!MTB"
        threat_id = "2147965235"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CountLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HTA Runner" ascii //weight: 1
        $x_1_2 = "mshta.exe" ascii //weight: 1
        $x_1_3 = "https://burning-edge.sbs/stats/randoms2/monitor.php?q=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CountLoader_ACL_2147966680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CountLoader.ACL!MTB"
        threat_id = "2147966680"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CountLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {f7 f9 8b c2 ff c0 89 44 24 30 44 8b 4c 24 30 4c 8d 05 c4 df 01 00 ba 04 01 00 00 48 8d 4c 24 40 e8 ?? ?? ?? ?? c7 44 24 28 01 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8d 4c 24 40 4c 8d 05 f8 df 01 00 48 8d 15 09 e0 01 00 33 c9}  //weight: 4, accuracy: Low
        $x_1_2 = "HTA Runner" wide //weight: 1
        $x_3_3 = "webdriver-select.vg" wide //weight: 3
        $x_2_4 = "burning-edge.sbs/stats/randoms3/monitor" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

