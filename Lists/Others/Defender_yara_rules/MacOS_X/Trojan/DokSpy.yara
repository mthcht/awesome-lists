rule Trojan_MacOS_X_DokSpy_A_2147721469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS_X/DokSpy.A"
        threat_id = "2147721469"
        type = "Trojan"
        platform = "MacOS_X: "
        family = "DokSpy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "killall Safari" ascii //weight: 1
        $x_1_2 = "sudo -u %@ %@ install tor" ascii //weight: 1
        $x_1_3 = "sudo -u %@ %@ services start tor" ascii //weight: 1
        $x_1_4 = "tcp4-LISTEN:5555,reuseaddr,fork,keepalive,bind=127.0.0.1" ascii //weight: 1
        $x_1_5 = "security add-trusted-cert -d -r trustRoot -k /Library/Keychains/S" ascii //weight: 1
        $x_1_6 = "paoyu7gub72lykuk.onion" ascii //weight: 1
        $x_1_7 = "chmod +x %@ && rm -f %@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

