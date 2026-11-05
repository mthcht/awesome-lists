rule Trojan_Win64_SLoader_A_2147935931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SLoader.A"
        threat_id = "2147935931"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ssst ik verstop me in notepad++" ascii //weight: 1
        $x_1_2 = "/d2.bin" ascii //weight: 1
        $x_1_3 = "nietmalicious.nl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_SLoader_PL_2147981579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SLoader.PL!MTB"
        threat_id = "2147981579"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "!N1L7BSvc0Lf3yUGAftzO4k24CKmto2nUW'HrhU2z5esyuczxbYxx08HGHKuf786awlRWEY7F7" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

