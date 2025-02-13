rule Trojan_Win64_Razrusheniye_YAN_2147929697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Razrusheniye.YAN!MTB"
        threat_id = "2147929697"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Razrusheniye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "victim of the razrusheniye ransomware!" ascii //weight: 10
        $x_1_2 = "We can decrypt these files" ascii //weight: 1
        $x_1_3 = "hours if you pay" ascii //weight: 1
        $x_1_4 = "will sent you a decryptor" ascii //weight: 1
        $x_1_5 = "system will be just as new" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

