rule Trojan_O97M_RunVBAPE_MP_2147955010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/RunVBAPE.MP!MSR"
        threat_id = "2147955010"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "RunVBAPE"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 74 72 53 72 63 46 69 6c 65 20 3d 20 90 01 04 57 69 6e 64 6f 77 73 5c 53 79 73 57 4f 57 36 34 5c 57 69 6e 64 6f 77 73 50 6f 77 65 72 53 68 65 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {73 74 72 53 72 63 46 69 6c 65 20 3d 20 ?? ?? ?? ?? 57 69 6e 64 6f 77 73 5c [0-8] 5c 63 6d 64 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {73 74 72 53 72 63 46 69 6c 65 20 3d 20 90 01 04 73 75 70 70 6f 72 74 5c 70 75 74 74 79 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "://github.com/itm4n/VBA-RunPE" ascii //weight: 1
        $x_5_5 = "strSrcArguments = \"-exec Bypass" ascii //weight: 5
        $x_5_6 = "baSrcFileContent = FileToByteArray(strSrcFile)" ascii //weight: 5
        $x_5_7 = "baSrcFileContent = StringToByteArray(strSrcPE)" ascii //weight: 5
        $x_5_8 = "Call RunPE(baSrcFileContent, strSrcArguments)" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

