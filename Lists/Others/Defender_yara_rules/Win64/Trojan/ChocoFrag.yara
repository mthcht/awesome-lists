rule Trojan_Win64_ChocoFrag_A_2147891456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ChocoFrag.A!dha"
        threat_id = "2147891456"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ChocoFrag"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 83 ec 28 66 c7 [0-3] 48 b8}  //weight: 10, accuracy: Low
        $x_10_2 = {48 81 fa 00 10 00 00 72 15 48 83 c2 27 ?? ?? ?? ?? ?? ?? ?? 48 83 c0 f8 48 83 f8 1f}  //weight: 10, accuracy: Low
        $x_1_3 = "ServiceMain" ascii //weight: 1
        $x_1_4 = "open fail" ascii //weight: 1
        $x_1_5 = "install ok -> %d" ascii //weight: 1
        $x_1_6 = "proc fail" ascii //weight: 1
        $x_1_7 = "read config fail" ascii //weight: 1
        $x_1_8 = "read config ok" ascii //weight: 1
        $x_1_9 = "open flash fail" ascii //weight: 1
        $x_1_10 = "open flash ok" ascii //weight: 1
        $x_1_11 = "id %d" ascii //weight: 1
        $x_1_12 = "main.dll" ascii //weight: 1
        $x_1_13 = "flash.dat" ascii //weight: 1
        $x_2_14 = "C:\\windows\\system32\\defragsvc.dll" ascii //weight: 2
        $x_2_15 = "C:\\WINDOWS\\SYSTEM32\\wbem\\WMIsvc.dll" ascii //weight: 2
        $x_2_16 = "C:\\Windows\\system32\\SDRSVC.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

