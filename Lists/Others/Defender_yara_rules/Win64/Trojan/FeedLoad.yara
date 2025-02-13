rule Trojan_Win64_FeedLoad_A_2147893102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FeedLoad.A!dha"
        threat_id = "2147893102"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FeedLoad"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {85 c0 0f 88 ?? ?? ?? ?? c7 ?? ?? ?? ef cd ab 89 c7 ?? ?? ?? 67 45 23 01 83 fd 08}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

