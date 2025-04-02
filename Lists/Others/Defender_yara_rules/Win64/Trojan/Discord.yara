rule Trojan_Win64_Discord_ARA_2147937593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Discord.ARA!MTB"
        threat_id = "2147937593"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "reporthttps://arsenite.su/logger/" ascii //weight: 2
        $x_2_2 = "\\injector.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

