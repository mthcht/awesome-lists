rule Trojan_MacOS_RealstStealer_B_2147904542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/RealstStealer.B!MTB"
        threat_id = "2147904542"
        type = "Trojan"
        platform = "MacOS: "
        family = "RealstStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.battlenetChecker" ascii //weight: 1
        $x_1_2 = "runtime.stealWork" ascii //weight: 1
        $x_1_3 = "main.getSafeStorageSecretKeys" ascii //weight: 1
        $x_1_4 = "main.binanceChecker" ascii //weight: 1
        $x_1_5 = "CCopyFFolderContents" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_RealstStealer_A_2147913713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/RealstStealer.A!MTB"
        threat_id = "2147913713"
        type = "Trojan"
        platform = "MacOS: "
        family = "RealstStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Profile /Downloads/cached_data/data/Cards.txt" ascii //weight: 1
        $x_1_2 = "data/Passwords.txt" ascii //weight: 1
        $x_1_3 = "dump-generic-passwords" ascii //weight: 1
        $x_1_4 = "modules/data_stealers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

