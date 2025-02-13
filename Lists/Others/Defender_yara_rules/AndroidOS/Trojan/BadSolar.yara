rule Trojan_AndroidOS_BadSolar_A_2147897155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/BadSolar.A!MTB"
        threat_id = "2147897155"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "BadSolar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yhnrfv" ascii //weight: 1
        $x_1_2 = "Lcom/SolARCS/SolClient/Client" ascii //weight: 1
        $x_1_3 = "DexClassLoader" ascii //weight: 1
        $x_1_4 = "CommandExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

