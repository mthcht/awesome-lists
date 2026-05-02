rule Trojan_MacOS_MiniRat_DA_2147968323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/MiniRat.DA!MTB"
        threat_id = "2147968323"
        type = "Trojan"
        platform = "MacOS: "
        family = "MiniRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alibaba.xyz/minirat/internal/crypto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

