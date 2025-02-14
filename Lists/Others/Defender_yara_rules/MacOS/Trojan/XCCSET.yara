rule Trojan_MacOS_XCCSET_ST_2147933514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/XCCSET.ST"
        threat_id = "2147933514"
        type = "Trojan"
        platform = "MacOS: "
        family = "XCCSET"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "echo " wide //weight: 1
        $x_1_2 = "curl -fskL -d " wide //weight: 1
        $x_1_3 = "os=$(uname -s)&p=" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 [0-32] 2e 00 72 00 75 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_5 = "| sh >/dev/null 2>&1 &" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

