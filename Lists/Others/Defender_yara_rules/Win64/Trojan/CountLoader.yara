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

