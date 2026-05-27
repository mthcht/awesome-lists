rule Trojan_Linux_FakeHub_DB_2147969964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/FakeHub.DB!MTB"
        threat_id = "2147969964"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "FakeHub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Q0I9Imh0dHA6Ly8yMTYu" wide //weight: 1
        $x_1_2 = "set +e; echo" wide //weight: 1
        $x_1_3 = "| base64 -d" wide //weight: 1
        $x_1_4 = "| bash" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

