rule Trojan_Win64_Tinplate_A_2147919489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tinplate.A!dha"
        threat_id = "2147919489"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tinplate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "doingOnNet operation" ascii //weight: 1
        $x_1_2 = "doingOnDisk operation" ascii //weight: 1
        $x_1_3 = "doingOnNet.txt" ascii //weight: 1
        $x_1_4 = "doingOnDisk.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

