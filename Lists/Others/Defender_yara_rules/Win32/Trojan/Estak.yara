rule Trojan_Win32_Estak_EM_2147838001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Estak.EM!MTB"
        threat_id = "2147838001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Estak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 ec 04 c7 04 24 10 14 40 00 c3}  //weight: 5, accuracy: High
        $x_1_2 = {81 fb f4 01 00 00 75 05 bb 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 ff f4 01 00 00 75 05 bf 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

