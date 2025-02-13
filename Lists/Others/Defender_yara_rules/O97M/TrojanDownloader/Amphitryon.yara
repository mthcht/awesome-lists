rule TrojanDownloader_O97M_Amphitryon_MK_2147789387_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Amphitryon.MK!MTB"
        threat_id = "2147789387"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Amphitryon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 72 6f 67 72 61 6d 20 3d 20 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 24 70 61 74 68 20 3d 20 24 45 6e 76 3a 74 65 6d 70 2b 27 5c [0-16] 2e 65 78 65 27}  //weight: 1, accuracy: Low
        $x_1_2 = "$client.downloadfile('https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe',$path)" ascii //weight: 1
        $x_1_3 = "Start-Process -FilePath $path" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Amphitryon_SWA_2147930823_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Amphitryon.SWA!MTB"
        threat_id = "2147930823"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Amphitryon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "filePath = \"C:\\Users\\\" & Environ(\"USERNAME\") & \"\\AppData\\Roaming\\startup.bat\"" ascii //weight: 2
        $x_2_2 = "networking.s3.ir-thr-at1.arvanstorage.ir/Payload.bat" ascii //weight: 2
        $x_1_3 = "%appdata%\\Payload.bat" ascii //weight: 1
        $x_1_4 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\startup.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

