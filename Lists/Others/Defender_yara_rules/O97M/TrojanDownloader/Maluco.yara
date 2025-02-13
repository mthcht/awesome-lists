rule TrojanDownloader_O97M_Maluco_KA_2147745282_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Maluco.KA"
        threat_id = "2147745282"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Maluco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 70 65 6e 20 65 6e 76 20 26 20 22 50 73 69 43 6f 6e 74 65 6e 74 5c 22 20 26 20 22 [0-30] 22 20 26 20 22 2e 62 61 74 22}  //weight: 1, accuracy: Low
        $x_1_2 = "Environ$(Chr$(65) & Chr$(112) & Chr$(112) & Chr$(68) & Chr$(97) & Chr$(116) & Chr$(97)) & Chr$(92)" ascii //weight: 1
        $x_1_3 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 72 67 65 74 46 72 61 6d 65 20 26 20 22 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 61 70 69 6b 65 79 2f [0-20] 2e 70 6e 67 27 2c 20 27 43 3a 5c 50 73 69 43 6f 6e 74 65 6e 74 5c [0-20] 2e 65 78 65 27 29 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_O97M_Maluco_KSH_2147766839_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:O97M/Maluco.KSH!MSR"
        threat_id = "2147766839"
        type = "TrojanDownloader"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Maluco"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(tilpS.ut$=mj$;txet$ nioj-=ut$;)txet$(esreveR::]yarrA[;)(yarrArahCoT" ascii //weight: 1
        $x_1_2 = "dnammoc- neddih elytSwodniW- llehsrewoP nim/ trats c/ DMC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

