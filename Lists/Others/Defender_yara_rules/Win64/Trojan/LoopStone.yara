rule Trojan_Win64_LoopStone_A_2147978836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LoopStone.A!dha"
        threat_id = "2147978836"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LoopStone"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "RangeStealer" ascii //weight: 5
        $x_5_2 = "range_stealer" ascii //weight: 5
        $x_1_3 = "src\\evasion\\mod.rs" ascii //weight: 1
        $x_1_4 = "src\\core\\persistence.rs" ascii //weight: 1
        $x_1_5 = "src\\core\\identity.rs" ascii //weight: 1
        $x_1_6 = "src\\exfil\\http.rs" ascii //weight: 1
        $x_1_7 = "src\\exfil\\telegram.rs" ascii //weight: 1
        $x_1_8 = "enable_string_obfuscation" ascii //weight: 1
        $x_1_9 = "enable_sandbox_detection" ascii //weight: 1
        $x_1_10 = "enable_basic_injection" ascii //weight: 1
        $x_1_11 = "exercise_id" ascii //weight: 1
        $x_1_12 = "No exfil endpoints configured" ascii //weight: 1
        $x_1_13 = "Admin elevated but no Users profiles found " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

