rule Ransom_Linux_Rhysida_A_2147895591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Rhysida.A!MTB"
        threat_id = "2147895591"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Rhysida"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Rhysida-0.1" ascii //weight: 1
        $x_1_2 = "esxcli system welcomemsg set -m" ascii //weight: 1
        $x_1_3 = "CriticalBreachDetected" ascii //weight: 1
        $x_1_4 = "/bin/rm -f" ascii //weight: 1
        $x_1_5 = {72 68 79 73 69 64 61 [0-88] 2e 6f 6e 69 6f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

