rule Trojan_Win64_Crypmodadv_ASG_2147895394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Crypmodadv.ASG!MTB"
        threat_id = "2147895394"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Crypmodadv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "XIIDoN9tKbCc1keiWnJs/_ClLItMgHPdmlm5kA8wm/wlZ95oh4HImE7JGTuWLY/hUuSDgsK6clPzACY61zK" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

