rule Trojan_JS_Koadic_F_2147735377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:JS/Koadic.F!attk"
        threat_id = "2147735377"
        type = "Trojan"
        platform = "JS: JavaScript scripts"
        family = "Koadic"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1200"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {5c 77 69 6e 33 32 5c 6d 69 6d 69 73 68 69 6d 5c 52 65 66 6c 65 63 74 69 76 65 44 4c 4c 49 6e 6a 65 63 74 69 6f 6e 5c [0-8] 52 65 6c 65 61 73 65 5c 6d 69 6d 69 73 68 69 6d 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_100_2 = "mimishim.dll" ascii //weight: 100
        $x_100_3 = "mimishim.x64.dll" ascii //weight: 100
        $x_1000_4 = "ReflectiveLoader@" ascii //weight: 1000
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1000_*) and 2 of ($x_100_*))) or
            (all of ($x*))
        )
}

