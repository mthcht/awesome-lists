rule Trojan_Win64_ChroHack_SB_2147753241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ChroHack.SB!MSR"
        threat_id = "2147753241"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ChroHack"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "afuocolento.it/wp-includes" wide //weight: 1
        $x_1_2 = "Set-Cookie" wide //weight: 1
        $x_1_3 = "CratClient.dll" ascii //weight: 1
        $x_1_4 = "atlTraceSecurity" wide //weight: 1
        $x_1_5 = "atlTraceCache" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

