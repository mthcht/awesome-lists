rule Trojan_MSIL_ZippyLoader_NEAA_2147839971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ZippyLoader.NEAA!MTB"
        threat_id = "2147839971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ZippyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 11 08 06 7e 06 00 00 04 11 06 28 13 00 00 0a 6f 1b 00 00 0a 00 11 08 07 7e 05 00 00 04 11 07 28 13 00 00 0a 6f 1b 00 00 0a 00 00 de 0d}  //weight: 10, accuracy: High
        $x_2_2 = "zippyshare.com/d/" wide //weight: 2
        $x_2_3 = "SecurityHealthSystray.exe" wide //weight: 2
        $x_2_4 = "Microsoft\\Vault\\TaskMaster.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

