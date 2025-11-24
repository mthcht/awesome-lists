rule Trojan_Win64_NeverlietStealer_CH_2147958137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NeverlietStealer.CH!MTB"
        threat_id = "2147958137"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NeverlietStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Go build ID: \"vY6rq5XqaNlnZowm5j5p/d9o5oA8cnX7kPEK2I97H/w7gNdCMiGcakCpcmjgdL/XamrmxhhlVgUsWccN3vc\"" ascii //weight: 2
        $x_2_2 = "Go build ID: \"HXraWpUPejmD3DfUf-Ei/7cY-AS9gpF6HimzbFakS/gPFA_w7rA0j6rJQlDCmb/oAEQKJ-KVUtjxR3mqkQ7\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

