rule Trojan_Win64_CoralWave_A_2147959334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoralWave.A"
        threat_id = "2147959334"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoralWave"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LZMA header invalid properties:" ascii //weight: 1
        $x_1_2 = "src\\peload.rs" ascii //weight: 1
        $x_1_3 = "src\\printable.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

