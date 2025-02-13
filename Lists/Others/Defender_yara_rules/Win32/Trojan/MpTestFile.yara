rule Trojan_Win32_MpTestFile_I_2147706091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTestFile.I"
        threat_id = "2147706091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTestFile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_INNOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "509dbbd9-c578-4fd7-b1de-8a5432ace7be" ascii //weight: 1
        $x_1_2 = "0aa5ff49-a083-4757-a0e3-6e4be6973764" ascii //weight: 1
        $x_1_3 = "0c7a9ee1-d8d3-4ba1-a949-f64895d001cd" ascii //weight: 1
        $x_1_4 = "eec977bd-d82d-4f22-8b63-2f2291d6e56a" ascii //weight: 1
        $x_1_5 = "c8d5ae9d-21af-48c2-89e0-ae60026c5ab0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

