rule Trojan_Win64_ShadyDeal_A_2147966162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ShadyDeal.A!dha"
        threat_id = "2147966162"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ShadyDeal"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ransome-as-a-service" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Pc\\vcrepo\\vcpkg\\" ascii //weight: 1
        $x_1_3 = "[ERROR] File processing failed:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

