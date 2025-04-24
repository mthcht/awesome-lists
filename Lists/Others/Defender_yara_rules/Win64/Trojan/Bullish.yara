rule Trojan_Win64_Bullish_A_2147939853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bullish.A!dha"
        threat_id = "2147939853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bullish"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mskmdjwo" ascii //weight: 1
        $x_1_2 = "dejfowhfjwlfekjfJOI" ascii //weight: 1
        $x_1_3 = "djvo2oejf2" ascii //weight: 1
        $x_1_4 = "romsifl" ascii //weight: 1
        $x_1_5 = "poepofjow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Bullish_B_2147939854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bullish.B!dha"
        threat_id = "2147939854"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bullish"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hkwhkhfww" ascii //weight: 1
        $x_1_2 = "hfwehjkwhefq" ascii //weight: 1
        $x_1_3 = "jJhqwhjhdq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

