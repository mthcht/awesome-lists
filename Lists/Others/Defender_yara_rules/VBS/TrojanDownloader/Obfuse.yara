rule TrojanDownloader_VBS_Obfuse_JK_2147755369_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:VBS/Obfuse.JK!MTB"
        threat_id = "2147755369"
        type = "TrojanDownloader"
        platform = "VBS: Visual Basic scripts"
        family = "Obfuse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sOut = sOut & Left(pOut, numDataBytes)" ascii //weight: 1
        $x_1_2 = {43 68 72 28 43 42 79 74 65 28 22 26 48 22 20 26 20 4d 69 64 28 6e 47 72 6f 75 70 2c 20 [0-2] 2c 20 [0-2] 29 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = "nGroup = 64 * nGroup + thisData" ascii //weight: 1
        $x_1_4 = "CreateObject(\"WScript.Shell\").Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

