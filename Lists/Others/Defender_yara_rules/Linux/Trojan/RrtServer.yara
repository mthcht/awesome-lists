rule Trojan_Linux_RrtServer_A_2147773045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/RrtServer.A!MTB"
        threat_id = "2147773045"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "RrtServer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rrootkit_crypto_rc4" ascii //weight: 1
        $x_1_2 = "invalid rrootkit message" ascii //weight: 1
        $x_1_3 = "/proc/sys/rrootkit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

