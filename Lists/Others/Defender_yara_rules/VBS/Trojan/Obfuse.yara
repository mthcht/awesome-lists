rule Trojan_VBS_Obfuse_D_2147751391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBS/Obfuse.D!MTB"
        threat_id = "2147751391"
        type = "Trojan"
        platform = "VBS: Visual Basic scripts"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RetVal = Shell(Filename, 0)" ascii //weight: 1
        $x_1_2 = "Filename = Filename & \"\\RUN_S.BAT\"" ascii //weight: 1
        $x_1_3 = "Cells(Isec2 + 1, Isec3 + 7) = Trim(TempStr)" ascii //weight: 1
        $x_1_4 = {49 66 20 49 73 65 63 31 20 3e 20 37 32 20 54 68 65 6e 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 49 73 65 63 32 20 3d 20 32 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 49 73 65 63 33 20 3d 20 49 73 65 63 33 20 2b 20 38 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 49 73 65 63 31 20 3d 20 31 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 45 6e 64 20 49 66}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

