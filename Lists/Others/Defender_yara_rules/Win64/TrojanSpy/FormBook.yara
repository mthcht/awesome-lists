rule TrojanSpy_Win64_FormBook_AKO_2147945359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/FormBook.AKO!MTB"
        threat_id = "2147945359"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "FormBook"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BunBubunKLagfsw" wide //weight: 3
        $x_4_2 = "GoldVekRogerS" wide //weight: 4
        $x_6_3 = "180.178.189.17" wide //weight: 6
        $x_5_4 = "GagikMaraguiSS" wide //weight: 5
        $x_2_5 = "www.ip-api.com" wide //weight: 2
        $x_1_6 = "line/?fields=147505" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

