rule Trojan_AndroidOS_Adbminer_A_2147923192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Adbminer.A!MTB"
        threat_id = "2147923192"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Adbminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "droidbot" ascii //weight: 1
        $x_1_2 = "com.ufo.miner" ascii //weight: 1
        $x_1_3 = "adb -s %s:5555 shell" ascii //weight: 1
        $x_1_4 = "/lock0.txt" ascii //weight: 1
        $x_1_5 = {74 6d 70 2f [0-6] 2e 61 70 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

