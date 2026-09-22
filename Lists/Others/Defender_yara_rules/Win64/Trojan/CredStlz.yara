rule Trojan_Win64_CredStlz_AB_2147978582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CredStlz.AB!MTB"
        threat_id = "2147978582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CredStlz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Harvesting Chrome browser data..." ascii //weight: 1
        $x_1_2 = "[HARVEST] Response will now be sent to C2..." ascii //weight: 1
        $x_1_3 = "[PAYLOAD] main() executing" ascii //weight: 1
        $x_1_4 = "[HARVEST] Request received, starting harvest..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

