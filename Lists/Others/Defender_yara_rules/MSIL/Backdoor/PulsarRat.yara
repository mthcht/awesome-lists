rule Backdoor_MSIL_PulsarRat_MK_2147965660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/PulsarRat.MK!MTB"
        threat_id = "2147965660"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PulsarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_25_1 = {35 00 70 72 ?? ?? 00 70 11 05 72 ?? ?? 00 70 28 ?? ?? 00 0a 73 ?? ?? 00 0a 13 06 11 06 16 6f ?? ?? 00 0a 11 06 17 6f ?? ?? 00 0a 11 06 17 6f ?? 00 00 0a 07}  //weight: 25, accuracy: Low
        $x_10_2 = "RUNNER_URL" ascii //weight: 10
        $x_3_3 = "-NoProfile -ExecutionPolicy Bypass -EncodedCommand" ascii //weight: 3
        $x_2_4 = "-NoProfile -ExecutionPolicy Bypass -File" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

