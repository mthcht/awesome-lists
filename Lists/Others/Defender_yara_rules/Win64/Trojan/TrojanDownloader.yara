rule Trojan_Win64_TrojanDownloader_NIT_2147920896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TrojanDownloader.NIT!MTB"
        threat_id = "2147920896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TrojanDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\remote_cs\\x64\\Release\\remote_cs.pdb" ascii //weight: 2
        $x_2_2 = "MXXFEGYCAYFCNYFFEMOOOOX" ascii //weight: 2
        $x_1_3 = "InternetOpenW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

