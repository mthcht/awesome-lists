rule Ransom_Win32_FRIEDEX_MR_2147744044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FRIEDEX.MR!MTB"
        threat_id = "2147744044"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FRIEDEX"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {28 df 89 84 24 ?? ?? ?? ?? 89 94 24 ?? ?? ?? ?? 8a 9c 24 ?? ?? ?? ?? 66 c7 84 24 ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 00 fb 88 18 8a 5c 24 ?? 80 f3 ?? 88 9c 24 ?? ?? ?? ?? 8a 5c 24 ?? 80 c3 ?? 8b 84 24 ?? ?? ?? ?? 35 ?? ?? ?? ?? 88 9c 24 09 00 8a 9c 24 ?? ?? ?? ?? b7}  //weight: 6, accuracy: Low
        $x_1_2 = "0OchannelnChromebookVPjacksono" wide //weight: 1
        $x_1_3 = "156bar.Kactionsfirst" wide //weight: 1
        $x_1_4 = "34I7vKnatively66webhe" ascii //weight: 1
        $x_1_5 = "zoingatorsMOl71HY" ascii //weight: 1
        $x_1_6 = "l1advancing53.Copies" wide //weight: 1
        $x_1_7 = "allowInternetthes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

