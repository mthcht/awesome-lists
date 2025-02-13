rule Trojan_Win64_AtlasClipper_A_2147851667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AtlasClipper.A!MTB"
        threat_id = "2147851667"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AtlasClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "regexp.(*Regexp).MatchString" ascii //weight: 2
        $x_2_2 = "regexp.(*Regexp).doMatch" ascii //weight: 2
        $x_2_3 = "D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}" ascii //weight: 2
        $x_2_4 = "(^|\\W)(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}($|\\W)" ascii //weight: 2
        $x_2_5 = "windows.CreateMutex" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

