rule TrojanDownloader_O97M_SilkParasite_GV_2147977381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/SilkParasite.GV!MTB"
        threat_id = "2147977381"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "SilkParasite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inputBytes(i) = inputBytes(i) Xor &H39" ascii //weight: 1
        $x_1_2 = "CreateSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0&)" ascii //weight: 1
        $x_1_3 = "wsh.Run \"\"\"\" & programPath & \"\"\"\", 1, False" ascii //weight: 1
        $x_1_4 = "uildDestPath1 = appDataPath & \"\\e\" + _" ascii //weight: 1
        $x_1_5 = "Sub AutoOpen()" ascii //weight: 1
        $x_1_6 = "ret = Process32Next(hSnapshot, procEntry)" ascii //weight: 1
        $x_1_7 = "CheckProcessAndRun targetPath" ascii //weight: 1
        $x_1_8 = "Replace(s, \" \", \"\"), vbCr, \"\"), vbLf, \"\"), vbCrLf, \"\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

