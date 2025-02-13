rule Trojan_Win64_Isator_A_2147731117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Isator.A!bit"
        threat_id = "2147731117"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Isator"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\itranslator\\itranslator.dll" ascii //weight: 1
        $x_1_2 = "gl.immereeako.info/gl.php?uid=" ascii //weight: 1
        $x_1_3 = "BHDwonloadUpdateFile" ascii //weight: 1
        $x_1_4 = "\\.\\iTranslatorCtrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

