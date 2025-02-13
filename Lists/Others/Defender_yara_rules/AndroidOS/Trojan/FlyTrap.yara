rule Trojan_AndroidOS_FlyTrap_A_2147788240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FlyTrap.A"
        threat_id = "2147788240"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FlyTrap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ynsuper" ascii //weight: 2
        $x_2_2 = {43 6f 6f 6b 69 65 4d 61 6e 61 67 65 72 2e 67 65 74 49 6e 73 74 61 6e 63 e2 80 a6 2e 55 52 4c 5f 47 45 54 5f 43 4f 4f 4b 49 45 5f 46 41 43 45 42 4f 4f 4b}  //weight: 2, accuracy: High
        $x_2_3 = "/LoginActivity$setUpDefaultWebClient$1" ascii //weight: 2
        $x_2_4 = "; password: " ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

