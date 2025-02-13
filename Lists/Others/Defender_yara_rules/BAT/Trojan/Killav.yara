rule Trojan_BAT_Killav_W_155910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:BAT/Killav.W"
        threat_id = "155910"
        type = "Trojan"
        platform = "BAT: Basic scripts"
        family = "Killav"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%%bullshit%%mpf%%_%l%sars%%qsk%%pg56%%msn%%f% %q%%.%%w%%rma%%g6f%%avp_club%&%ten%%/%%ram%%x%%b%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

