rule TrojanSpy_Win64_Derusbi_2147711364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/Derusbi!dha"
        threat_id = "2147711364"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PCC_CMD" ascii //weight: 1
        $x_1_2 = "PCC_FILE" ascii //weight: 1
        $x_1_3 = "PCC_PROXY" ascii //weight: 1
        $x_1_4 = "rundll32 \"%s\", Run32 %s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

