rule Backdoor_MSIL_Omaneat_B_2147721711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Omaneat.B"
        threat_id = "2147721711"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Omaneat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(Start Attack)" ascii //weight: 1
        $x_1_2 = "starting flood" ascii //weight: 1
        $x_1_3 = "SYN Attack Started" ascii //weight: 1
        $x_1_4 = "TCP Attack Started" ascii //weight: 1
        $x_1_5 = {00 64 64 6f 73}  //weight: 1, accuracy: High
        $x_1_6 = {00 6d 69 6e 65 72}  //weight: 1, accuracy: High
        $x_1_7 = "startup_persistence=" ascii //weight: 1
        $x_1_8 = "file_persistence=" ascii //weight: 1
        $x_1_9 = "mutex_persistence_module=" ascii //weight: 1
        $x_1_10 = "SOCKS_USERNAME=" ascii //weight: 1
        $x_1_11 = "SOCKS_PASSWORD=" ascii //weight: 1
        $x_1_12 = "<BrowserBack>" ascii //weight: 1
        $x_1_13 = "<Volume->" ascii //weight: 1
        $x_1_14 = "<Pause/Break>" ascii //weight: 1
        $x_1_15 = "Miner Thread" ascii //weight: 1
        $x_1_16 = "DDoS Thread" ascii //weight: 1
        $x_1_17 = "Reverse Socks5" ascii //weight: 1
        $x_1_18 = "keylog_filter" ascii //weight: 1
        $x_1_19 = "GetKeyloggerFilter" ascii //weight: 1
        $x_1_20 = "BK_RUN_ONCE=" ascii //weight: 1
        $x_1_21 = "PersistenceModuleInjector" ascii //weight: 1
        $x_2_22 = "resopnse was nothing and there is nothing to decrypt!" ascii //weight: 2
        $x_2_23 = "Reseting connector!" ascii //weight: 2
        $x_2_24 = "Hahshes do not have the same lenght." ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

