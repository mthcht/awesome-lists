rule TrojanDownloader_O97M_DCRat_PA_2147925055_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/DCRat.PA!MTB"
        threat_id = "2147925055"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 67 4b 65 79 20 3d 20 22 48 4b 45 59 5f 43 55 52 52 22 20 2b 20 22 45 4e 54 5f 55 53 [0-8] 45 52 5c 53 4f [0-8] 46 54 22 20 2b 20 22 57 41 52 45 5c 4d 69 63 22 20 2b 20 22 72 6f 73 6f 66 74 5c 57 69 6e 22 20 2b 20 22 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 22 20 2b 20 22 6e 74 56 65 72 73 [0-8] 69 6f 6e 5c 57 69 6e 22 20 2b 20 22 64 6f 77 73 5c 4c 22 20 2b 20 22 4f 41 44 22}  //weight: 1, accuracy: Low
        $x_1_2 = "= CreateObject(\"WScr\" + \"ipt.Sh\" + \"ell\")" ascii //weight: 1
        $x_1_3 = "fileNameDigitalRSASignature = \"Use\" + \"rCac\" + \"he.in\" + \"i.h\" + \"ta" ascii //weight: 1
        $x_1_4 = "fileNameCHECKSUM = \"Us\" + \"erC\" + \"ac\" + \"he.i\" + \"ni" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

