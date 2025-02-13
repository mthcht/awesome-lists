rule Trojan_Linux_XMRig_A_2147774302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/XMRig.gen!A!!XMRig.gen!A"
        threat_id = "2147774302"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "XMRig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "XMRig: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "URL of mining server" ascii //weight: 1
        $x_1_2 = "password for mining server" ascii //weight: 1
        $x_1_3 = "--cpu-max-threads-hint=N" ascii //weight: 1
        $x_1_4 = "--donate-level=N" ascii //weight: 1
        $x_1_5 = "\"nicehash\": false" ascii //weight: 1
        $x_1_6 = "\"algo\": \"cryptonight\"" ascii //weight: 1
        $x_1_7 = "'h' hashrate, 'p' pause, 'r' resume" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Linux_XMRig_B_2147775882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/XMRig.gen!B!!XMRig.gen!B"
        threat_id = "2147775882"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "XMRig"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "XMRig: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"donate-level\":" ascii //weight: 1
        $x_1_2 = "\"donate-over-proxy\":" ascii //weight: 1
        $x_1_3 = "\"nicehash\":" ascii //weight: 1
        $x_1_4 = "\"scratchpad_prefetch_mode\":" ascii //weight: 1
        $x_1_5 = "\"astrobwt-max-size\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

