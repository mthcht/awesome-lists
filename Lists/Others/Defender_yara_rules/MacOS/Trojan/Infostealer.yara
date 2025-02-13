rule Trojan_MacOS_Infostealer_A_2147842338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Infostealer.A"
        threat_id = "2147842338"
        type = "Trojan"
        platform = "MacOS: "
        family = "Infostealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "system_profiler SPHardwareDataType >" ascii //weight: 1
        $x_1_2 = "/Library/Application Support/zoom.us/data/zoomus.enc.db" ascii //weight: 1
        $x_1_3 = "/Desktop -maxdepth 1 -name \"*.txt\" >" ascii //weight: 1
        $x_1_4 = "/Documents -maxdepth 1 -name \"*.txt\" >" ascii //weight: 1
        $x_1_5 = "/dev/null find-generic-password -ga 'Chrome'" ascii //weight: 1
        $x_1_6 = "awk '{print $2}' >" ascii //weight: 1
        $x_1_7 = ".txt && rm -Rf" ascii //weight: 1
        $x_1_8 = "userbot=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

