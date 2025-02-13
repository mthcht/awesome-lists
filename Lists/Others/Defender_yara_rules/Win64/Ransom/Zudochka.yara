rule Ransom_Win64_Zudochka_LK_2147850041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Zudochka.LK!MTB"
        threat_id = "2147850041"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Zudochka"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 ff c6 80 f3 0c 48 8b 85 ?? ?? 00 00 88 1c 10 48 ff 85 ?? ?? 00 00 48 ff c7 4c 39 f6 73 28 0f b6 1f 48 8b 95 ?? ?? 00 00 48 3b 95 ?? ?? 00 00 75 ce}  //weight: 3, accuracy: Low
        $x_1_2 = "HACKED.png" ascii //weight: 1
        $x_1_3 = "Pentest\\source\\repos\\rustware\\rustware\\target\\release\\deps\\rustware.pdb" ascii //weight: 1
        $x_1_4 = ".rsm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

