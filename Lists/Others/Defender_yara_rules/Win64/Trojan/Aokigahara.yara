rule Trojan_Win64_Aokigahara_AG_2147981132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Aokigahara.AG!MTB"
        threat_id = "2147981132"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Aokigahara"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X-Chunk-Index" ascii //weight: 1
        $x_1_2 = "X-Build-ID" ascii //weight: 1
        $x_1_3 = "AKGRES" ascii //weight: 1
        $x_1_4 = "AISessions" ascii //weight: 1
        $x_1_5 = "aokigahara" ascii //weight: 1
        $x_1_6 = "screenshot" ascii //weight: 1
        $x_1_7 = "\\pipe\\akg_%lx_%lx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

