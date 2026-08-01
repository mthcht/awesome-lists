rule Trojan_MacOS_Suspbase64ddecode_Z_2147975102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Suspbase64ddecode.Z!MTB"
        threat_id = "2147975102"
        type = "Trojan"
        platform = "MacOS: "
        family = "Suspbase64ddecode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "base64 -d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

