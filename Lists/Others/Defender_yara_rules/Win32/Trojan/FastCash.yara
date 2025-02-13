rule Trojan_Win32_FastCash_EC_2147923922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FastCash.EC!MTB"
        threat_id = "2147923922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FastCash"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Win32\\Release\\MyFc.pdb" ascii //weight: 5
        $x_5_2 = "\\x64\\Debug\\MyFc.pdb" ascii //weight: 5
        $x_1_3 = "GXCR7299I9MOWS97" ascii //weight: 1
        $x_1_4 = "W7SLFSG4OPBJNAA8" ascii //weight: 1
        $x_1_5 = "tmp\\info.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

