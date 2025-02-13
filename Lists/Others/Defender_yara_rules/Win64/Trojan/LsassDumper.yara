rule Trojan_Win64_LsassDumper_SA_2147895417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LsassDumper.SA!MTB"
        threat_id = "2147895417"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LsassDumper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 ff c1 40 30 2c 18 3b 4c 24 ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {44 30 00 48 8d 40 ?? 48 83 ea ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

