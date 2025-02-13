rule Trojan_Win32_Beebone_DA_2147899384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Beebone.DA!MTB"
        threat_id = "2147899384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Beebone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AKADEMIELEVER" ascii //weight: 1
        $x_1_2 = "Optim Class" ascii //weight: 1
        $x_1_3 = "IRISHWOMEN" ascii //weight: 1
        $x_1_4 = "Teknologivurderingsprojekters" ascii //weight: 1
        $x_1_5 = "SOLDEBRODERS" ascii //weight: 1
        $x_1_6 = "Sportsfiskerforbundenes8" ascii //weight: 1
        $x_1_7 = "Dagpengelovenes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

