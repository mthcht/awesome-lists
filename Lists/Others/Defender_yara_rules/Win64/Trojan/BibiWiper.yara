rule Trojan_Win64_BibiWiper_CCDD_2147894442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BibiWiper.CCDD!MTB"
        threat_id = "2147894442"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BibiWiper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[+] Round %d" ascii //weight: 1
        $x_1_2 = "[+] Path: %s" ascii //weight: 1
        $x_1_3 = "[+] CPU cores: %d" ascii //weight: 1
        $x_1_4 = "Threads: %d" ascii //weight: 1
        $x_1_5 = "lla/ teIuq/ swodahs   eteled nimdassv  c/ exe.dmc" ascii //weight: 1
        $x_1_6 = "teled ypocwodahs cimw c/ exe.dmc" ascii //weight: 1
        $x_1_7 = "seruliafllaerongi ycilopsutatstoob }tluafed{ tes / tidedcb c / exe.dmc" ascii //weight: 1
        $x_1_8 = "on delbaneyrevocer }tluafed{ tes/ tidedcb c/ exe.dmc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

