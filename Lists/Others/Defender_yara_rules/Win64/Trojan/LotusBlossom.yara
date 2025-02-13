rule Trojan_Win64_LotusBlossom_D_2147749602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LotusBlossom.D!dha"
        threat_id = "2147749602"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LotusBlossom"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{B6E56F0C-F1B75B7F}" ascii //weight: 1
        $x_1_2 = "LoadDLL4.dll" ascii //weight: 1
        $x_1_3 = "nssdll@@3HA" ascii //weight: 1
        $x_1_4 = "StartUp" ascii //weight: 1
        $x_1_5 = "fnabcssdll@@YAHXZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

