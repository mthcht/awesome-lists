rule Trojan_Win64_Oxloader_CA_2147972206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Oxloader.CA!MTB"
        threat_id = "2147972206"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Oxloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 30 3c 0a 44 02 3c 0a e2 f6}  //weight: 10, accuracy: High
        $x_10_2 = {48 ff c3 49 c1 ea ?? 48 ff cb 81 40 ?? ?? ?? ?? ?? 48 0f 44 db eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

