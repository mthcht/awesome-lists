rule Trojan_Win32_Fiestaek_CCIB_2147909159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fiestaek.CCIB!MTB"
        threat_id = "2147909159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fiestaek"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 10 90 80 ca 60 03 da d1 e3 03 45 10 8a 08 84 c9 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

