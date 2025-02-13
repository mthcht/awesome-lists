rule Trojan_Win64_Minxer_A_2147689582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Minxer.gen!A"
        threat_id = "2147689582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Minxer"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Usage: minerd [OPTIONS]" ascii //weight: 1
        $x_1_2 = "getwork\", \"params\": [ \"%s\" ], \"id\":1" ascii //weight: 1
        $x_1_3 = "%d miner threads started, using '%s' algorithm." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

