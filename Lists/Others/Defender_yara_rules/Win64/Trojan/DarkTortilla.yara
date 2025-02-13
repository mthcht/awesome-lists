rule Trojan_Win64_DarkTortilla_MM_2147899060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DarkTortilla.MM!MTB"
        threat_id = "2147899060"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SendEffectively" ascii //weight: 3
        $x_1_2 = "fronttechnological.exe" ascii //weight: 1
        $x_1_3 = "Wextract" ascii //weight: 1
        $x_1_4 = "IXP000.TMP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

