rule Trojan_MSIL_kryptic_2147849322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/kryptic.gen!MTB"
        threat_id = "2147849322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "kryptic"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 09 11 04 6f ?? ?? ?? ?? 13 06 08 12 06 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 11 04 17 58 13 04 11 04 07 6f ?? ?? ?? ?? 32 d8}  //weight: 10, accuracy: Low
        $x_1_2 = "GetObject" ascii //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
        $x_1_4 = "CurrentDomain" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

