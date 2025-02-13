rule Trojan_Win32_DelExe_C_2147633338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelExe.C"
        threat_id = "2147633338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelExe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "title WiNdOwS KiLLeR MaDe By HTC.SpLinTerCeLL" ascii //weight: 3
        $x_2_2 = "Del C:\\WINDOWS\\system32\\cmd.exe /q" ascii //weight: 2
        $x_1_3 = "START /max http://" ascii //weight: 1
        $x_2_4 = "REN *.DOC *.js" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

