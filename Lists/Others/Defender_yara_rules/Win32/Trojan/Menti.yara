rule Trojan_Win32_Menti_GNE_2147924859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Menti.GNE!MTB"
        threat_id = "2147924859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Menti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1b e6 ec 37 e6 5e 30 10}  //weight: 5, accuracy: High
        $x_5_2 = {44 00 34 00 32 00 37 00 46 ?? 38 00 32 00 44}  //weight: 5, accuracy: Low
        $x_1_3 = "file.tky" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

