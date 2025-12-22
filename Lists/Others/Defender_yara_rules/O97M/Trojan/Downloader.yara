rule Trojan_O97M_Downloader_PK_2147744422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Downloader.PK!MTB"
        threat_id = "2147744422"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 22 22 20 26 20 22 5c [0-10] 2e 22 20 26 20 22 22 20 26 20 22 6a 22 20 26 20 22 22 20 26 20 22 73 22 20 26 20 22 22 20 26 20 22 65 22}  //weight: 1, accuracy: Low
        $x_1_2 = {22 73 22 20 26 20 22 22 20 26 20 22 68 22 20 26 20 [0-10] 20 26 20 22 65 6c 6c 22}  //weight: 1, accuracy: Low
        $x_1_3 = "VBA.CallByName VBA.CreateObject(\"W\" + \"\" + \"Scrip\" & \"t.\"" ascii //weight: 1
        $x_1_4 = {22 52 22 20 26 20 [0-10] 20 26 20 22 75 6e 22 2c 20 56 62 4d 65 74 68 6f 64 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Downloader_SX_2147767446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Downloader.SX!MTB"
        threat_id = "2147767446"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Downloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 5c 47 72 61 76 69 74 79 5c 47 72 61 76 69 74 79 32 [0-6] 70 6e 67 21 [0-6] 68 74 74 70 3a 2f 2f 65 72 69 6b 76 61 6e 77 65 6c 2e 6e 6c 2f 78 79 71 66 6f 73 6e 6d 63 6d 71 2f}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateDirectoryA" ascii //weight: 1
        $x_1_3 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_4 = {65 78 70 6c 6f 72 65 72 [0-10] 3a 5c 47 72 61 76 69 74 79 5c 47 72 61 76 69 74 79 32 5c [0-10] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Downloader_BP_2147959883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Downloader.BP!MSR"
        threat_id = "2147959883"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Downloader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "scriptUrl = \"https://cloud-storage.art/doc/Y1.ps1\"" ascii //weight: 1
        $x_1_2 = "tempDir = \"C:\\Temp\"" ascii //weight: 1
        $x_1_3 = "scriptPath = tempDir & \"\\Y1.ps1\"" ascii //weight: 1
        $x_1_4 = "shell.Run \"PowerShell -NoProfile -ExecutionPolicy RemoteSigned -File \"\"\" & scriptPath & \"\"\"\", 0, True" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

