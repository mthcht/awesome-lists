rule Trojan_MacOS_XCSSET_B_2147789300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.B"
        threat_id = "2147789300"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5f 54 74 43 43 [0-16] 64 [0-2] 57 65 62 53 6f 63 6b 65 74 31 30 57 53 52 65 73 70 6f 6e 73 65}  //weight: 1, accuracy: Low
        $x_1_2 = "d/Worker.swift" ascii //weight: 1
        $x_1_3 = {48 b8 50 61 67 65 2e 67 65 74 48 89 ?? ?? 48 b8 43 6f 6f 6b 69 65 73 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCSSET_J_2147794885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.J"
        threat_id = "2147794885"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HaC80bwXscjqZ7KM6VOxULOB534" ascii //weight: 1
        $x_1_2 = "No writable apps were found and modded. Exiting." ascii //weight: 1
        $x_1_3 = "Resetting all cookies, payloads, cors targets" ascii //weight: 1
        $x_1_4 = "CSP Bypass disabled. Enabling" ascii //weight: 1
        $x_1_5 = "grep -q 'remote-debugging-port=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_XCSSET_AZ_2147933834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCSSET.AZ"
        threat_id = "2147933834"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCSSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sh -c" wide //weight: 1
        $x_1_2 = "bash -c" wide //weight: 1
        $x_5_3 = "grep -qF '.zshrc_aliases' ~/.zshrc || echo '[ -f $HOME/.zshrc_aliases ] && . $HOME/.zshrc_aliases' >> ~/.zshrc" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

