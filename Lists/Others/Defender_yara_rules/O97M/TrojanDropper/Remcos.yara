rule TrojanDropper_O97M_Remcos_PDB_2147830509_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Remcos.PDB!MTB"
        threat_id = "2147830509"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&jttoc=tyqlhku()+\"\"+g1()+g2()+\"-\"+g3()+g4()pathy=" ascii //weight: 1
        $x_1_2 = "bdfdf=t8g0f.open(v0df+\"\\citwz.bat\")endfunctionfunctionrev(s)dimpforp=len(s)to1step-1rev=rev&mid(s,p,1)nextendfunctionfunctionikfwq()" ascii //weight: 1
        $x_1_3 = "omwmlf=pathy+\"\\citwz.bat\"'youcanspecifyherethetextfilenameyouwanttocreate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_O97M_Remcos_PDC_2147831371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Remcos.PDC!MTB"
        threat_id = "2147831371"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "=range(\"a1\").valueendfunction" ascii //weight: 1
        $x_1_2 = ".self.invokeverb\"pa\"+\"ste\"endfunctionprivatefunction" ascii //weight: 1
        $x_1_3 = {2e 6f 70 65 6e 28 [0-5] 2b 22 5c [0-10] 2e 6a 22 2b 22 73 22 29 65 6e 64 73 75 62 73 75 62 [0-15] 28 00 29 6e 61 6d 65}  //weight: 1, accuracy: Low
        $x_1_4 = {63 6f 6e 73 74 75 73 65 72 5f 70 72 6f 66 69 6c 65 3d 26 68 32 38 26 61 63 74 69 76 65 73 68 65 65 74 2e 6f 6c 65 6f 62 6a 65 63 74 73 28 31 29 2e 63 6f 70 79 73 65 74 [0-6] 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 6d 65 72 6d 6b 64 28 29 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

