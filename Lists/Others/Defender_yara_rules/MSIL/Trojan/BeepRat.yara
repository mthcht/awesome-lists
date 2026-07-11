rule Trojan_MSIL_BeepRat_ABXB_2147973299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BeepRat.ABXB!MTB"
        threat_id = "2147973299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BeepRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "HFY.Properties.Resources" wide //weight: 5
        $x_1_2 = "connectionString" ascii //weight: 1
        $x_1_3 = "\\data.dll;Version=" ascii //weight: 1
        $x_1_4 = "select hd,sheng,shi from hfy_hd" ascii //weight: 1
        $x_1_5 = "InterNetwork" ascii //weight: 1
        $x_1_6 = "temp.bin" ascii //weight: 1
        $x_1_7 = "config.ini" ascii //weight: 1
        $x_2_8 = "tcc.exe" ascii //weight: 2
        $x_2_9 = "LuaJit.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

