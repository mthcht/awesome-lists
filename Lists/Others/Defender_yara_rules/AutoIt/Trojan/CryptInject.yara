rule Trojan_AutoIt_CryptInject_YA_2147734561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AutoIt/CryptInject.YA!MTB"
        threat_id = "2147734561"
        type = "Trojan"
        platform = "AutoIt: AutoIT scripts"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$exec ( \"StringSplit\" ) , $exec ( \"binarytostring\" ) , $exec ( \"asc\" ) , $exec ( \"bitxor\" ) , $exec ( \"stringlen\" ) , $exec (" wide //weight: 1
        $x_1_2 = "@HomeDrive & \"\\windows\\microsoft.net\\framework\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

