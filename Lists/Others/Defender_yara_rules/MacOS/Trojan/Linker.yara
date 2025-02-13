rule Trojan_MacOS_Linker_2147742473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Linker"
        threat_id = "2147742473"
        type = "Trojan"
        platform = "MacOS: "
        family = "Linker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DMGHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "2pvd64xrf3" ascii //weight: 2
        $x_2_2 = "mastura fenny" ascii //weight: 2
        $x_1_3 = {42 5a 68 31 31 41 59 26 ?? ?? 34 ae 33 9e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

