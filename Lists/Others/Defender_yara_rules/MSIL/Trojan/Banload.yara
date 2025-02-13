rule Trojan_MSIL_Banload_PSWH_2147889354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Banload.PSWH!MTB"
        threat_id = "2147889354"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 72 2b 00 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 2c 07 06 28 ?? 00 00 0a 26 de 03 26 de 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Banload_GXQ_2147910695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Banload.GXQ!MTB"
        threat_id = "2147910695"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".NET Reactor" ascii //weight: 1
        $x_1_2 = "/c net stop MemDrv & sc delete MemDrv & sc stop KProcessHacker2" ascii //weight: 1
        $x_1_3 = "sc delete KProcessHacker2 & sc stop WinMRW2 & sc delete WinMRW2" ascii //weight: 1
        $x_1_4 = "\\credentials.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

