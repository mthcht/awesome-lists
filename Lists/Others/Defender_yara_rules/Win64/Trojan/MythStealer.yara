rule Trojan_Win64_MythStealer_BSA_2147945148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MythStealer.BSA!MTB"
        threat_id = "2147945148"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MythStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Myth-Keymain" ascii //weight: 4
        $x_7_2 = "myth.cocukporno.lol/screen | Victim" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

